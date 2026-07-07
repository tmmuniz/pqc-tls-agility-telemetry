from __future__ import annotations

from typing import Any

import boto3


def resolve_ec2_instance_by_tag(
    *,
    region: str,
    tag_key: str = "deviceType",
    tag_value: str = "QDevice",
    require_ssm_online: bool = False,
) -> dict[str, Any]:
    """Return the most recently launched running EC2 instance matching a tag.

    The lab intentionally uses a stable device tag so GitHub Actions and the
    telemetry collector do not need to read Terraform outputs just to find the
    instance.
    """

    ec2 = boto3.client("ec2", region_name=region)
    filters = [
        {"Name": f"tag:{tag_key}", "Values": [tag_value]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ]
    response = ec2.describe_instances(Filters=filters)
    instances = [
        instance
        for reservation in response.get("Reservations", [])
        for instance in reservation.get("Instances", [])
    ]

    if not instances:
        raise RuntimeError(f"No running EC2 instance found with tag {tag_key}={tag_value} in {region}.")

    instances.sort(key=lambda item: item.get("LaunchTime"))
    selected = instances[-1]
    instance_id = selected["InstanceId"]

    ssm_ping_status = None
    if require_ssm_online:
        ssm = boto3.client("ssm", region_name=region)
        ssm_response = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        info = ssm_response.get("InstanceInformationList", [])
        ssm_ping_status = info[0].get("PingStatus") if info else "NotRegistered"
        if ssm_ping_status != "Online":
            raise RuntimeError(f"EC2 instance {instance_id} matched tag {tag_key}={tag_value}, but SSM status is {ssm_ping_status}.")

    tags = {tag.get("Key"): tag.get("Value") for tag in selected.get("Tags", [])}
    return {
        "instance_id": instance_id,
        "public_ip": selected.get("PublicIpAddress"),
        "private_ip": selected.get("PrivateIpAddress"),
        "instance_type": selected.get("InstanceType"),
        "launch_time": selected.get("LaunchTime").isoformat().replace("+00:00", "Z") if selected.get("LaunchTime") else None,
        "availability_zone": selected.get("Placement", {}).get("AvailabilityZone"),
        "tags": tags,
        "resolved_by": {
            "tag_key": tag_key,
            "tag_value": tag_value,
        },
        "ssm_ping_status": ssm_ping_status,
    }
