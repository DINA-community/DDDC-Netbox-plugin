# Datamodel within Netbox

Using Netbox in industrial control systems (ICS), the [Data Model of Netbox](https://netboxlabs.com/docs/netbox/en/stable/) has to be modified by custom fields and plugins. Still, there are some major adjustments to be made for the device type in order to use it for matching the asset data base with the Common Security Advisory Framework [CSAF](https://csaf.io).

## Datamodel for OT environment

With the [asset administration shell](https://webstore.iec.ch/publication/65628), there will be plenty of information about a device. However, which of those should be used for mapping vulnerabilities to a device? In the following table three documents of the IDTA are used to identify attributes for vulnerability mapping with CSAF and where this attributes can or should be find in Netbox.

### Legend

```markdown
    * ❓ = The attribution is unclear
    * ❗ = There is a conflict about this attribute which is addressed by the link
    * ℹ️ = There is information about this attribute which is addressed by the link
    * 🔨 = Adjustments to the current state of the DDDC plugin are necessary (used only in Table2)
```

*Table 1: Information for describing a device for vulnerability matching.*

| AAS | Netbox | CSAF | Description from AAS (mostly) | Relevant for CSAF matching                     | Source |
|  -           |  - | -  |- | - | - |
| Manufacturer Name| [Manufacturer:Name](#manufacturer-name) | vendor | Legally valid designation of the natural or judicial body which is directly responsible for the design, production, packaging and labeling of a product in respect to its being brought into the market |Yes | [IDTA 02003 1 2](#idta-02003-1-2) |
| Manufacturer Part number| [DeviceType:part_number](#part-number) | sku |unique product identifier of the manufacturer, also called [article number](#idta-02006-2-0)| Yes |  [IDTA 02003 1 2](#idta-02003-1-2) |
| Manufacturer Order Code| DeviceType:order_code | N/A | By manufactures issued unique combination of numbers and letters used to identify the device for ordering. | No | [IDTA 02003 1 2](#idta-02003-1-2) |
| Manufacturer Product Designation | :question: device:comments | optional [/document/notes_t/ (line 340-400)](https://github.com/oasis-tcs/csaf/blob/master/csaf_2.0/json_schema/csaf_json_schema.json) | short description of the product, product group or function | No | [IDTA 02003 1 2](#idta-02003-1-2) |
| Manufacturer Product Root| :question: deviceType:Role | N/A | Top level of a 3 level manufacturer specific product hierarchy (e. g. flow meter) | No | [IDTA 02006-2-0](#idta-02006-2-0)  |
| Manufacturer Product Family | [DeviceType:family](#device-family) | product_family |2nd level of a 3 level manufacturer specific product hierarchy | yes | [IDTA 02006-2-0](#idta-02006-2-0) |
| Manufacturer Product Type | [DeviceType:model](#model-number)| product_name | Characteristic to differentiate between different products of a product family or special variants. :information_source: One of the two properties Manufacturer `Product Family` or Manufacturer `Product Type`  must be provided according to EU Machine Directive 2006/42/EC.| Yes | [IDTA 02006-2-0](#idta-02006-2-0) |
| *unknown* | [device:Description](#device-description) | x_generic_uris | :information_source: own additional level to a 3 level manufacturer specific product hierarchy| Yes | *unknown* |
| serial number| [Device:serial_number](#serial-number) | serial_number |unique combination of numbers and letters used to identify the device once it has been manufactured | Yes | [IDTA 02006-2-0](#idta-02006-2-0) |
| Year of Construction| [Device:YoC](#year-of-construct) | N/A| year as completion date of object | Yes | [IDTA 02006-2-0](#idta-02006-2-0) |
| Date of Manufacture| N/A | N/A| Date from which the production and / or development process is completed or from which a service is provided completely |No | [IDTA 02006-2-0](#idta-02006-2-0) |
| HardwareVersion| DeviceType:hardware_version| product_version and product_version_range| :information_source: [Version](#version-number)  of the hardware supplied with the device|Yes | [IDTA 02006-2-0](#idta-02006-2-0) |
| FirmwareVersion| [Software:version](#version-number) + flag "is firmware"| product_version and product_version_range| :information_source: [Version](#version-number) of the firmware supplied with the device|Yes | [IDTA 02006-2-0](#idta-02006-2-0) |
| SoftwareVersion| [Software:version](#version-number)| product_version and product_version_range| :information_source: [Version](#version-number) of the software used by the device |Yes | [IDTA 02006-2-0](#idta-02006-2-0) |
| URI | [x_generic_uris](#x_generic_uris) | x_generic_uris |Unique global identification of the product using a universal resource identifier (URI)| Yes | [IDTA 02007-1-0](#idta-02007-1-0) |
| SoftwareType | [SoftwareType](#software-type) | N/A |The type of the software (category, e.g. Runtime, Application, Firmware, Driver, etc.) | Yes | [IDTA 02007-1-0](#idta-02007-1-0) |
| Version Name| [Software:version_name](#software-name) | x_generic_uris |The name this particular version is given (e. g. focal fossa) | Yes | [IDTA 02007-1-0](#idta-02007-1-0) |
| Version Info| Version Info | N/A | Provides a textual description of most relevant characteristics of the version of the software | No | [IDTA 02007-1-0](#idta-02007-1-0) |
| Manufacturer Name | [Manufacturer Name](#manufacturer-name)  | vendor in product_tree for this specific product| Creator of the software | Yes | [IDTA 02007-1-0](#idta-02007-1-0) |
| *unknown* | :question:Device:asset_tag / Device:Inventory or Software:x_generic_uris | x_generic_uris | Link to other company intern products like SAP | Yes | *unknown*|

### Literature

#### IDTA 02003-1-2

- **Title**: Generic Frame for Technical Data for Industrial Equipment in Manufacturing.
- **Section**: SMC GeneralInformation
- **Publisher**: Industrial digital twin Association
- **Year**: 2022
- **Source**: [IDTA Homepage](https://industrialdigitaltwin.org/wp-content/uploads/2022/10/IDTA-02003-1-2_Submodel_TechnicalData.pdf)

#### IDTA 02006-2-0

- **Title**: Digital Nameplate for Industrial Equipment
- **Section**: Nameplate
- **Publisher**: Industrial digital twin Association
- **Year**: 2022
- **Source**: [IDTA Homepage](https://industrialdigitaltwin.org/wp-content/uploads/2022/10/IDTA-02006-2-0_Submodel_Digital-Nameplate.pdf)

#### IDTA 02007-1-0

- **Title**: Nameplate for Software in Manufacturing
- **Section**: SoftwareNameplateType
- **Publisher**: Industrial digital twin Association
- **Year**: 2023
- **Source**: [IDTA Homepage](https://industrialdigitaltwin.org/wp-content/uploads/2023/08/IDTA-02007-1-0_Submodel_Software-Nameplate.pdf)

## Data model in Netbox

*Table 2: Datam odel for Netbox plugins by DINA community.*
|Name   | Netbox | Field | Desciption/Purpose | Example |
| - | - | - | - | - |
|Article Number         | ❗ DeviceType:part_number | :hammer: replace by part_number:hammer:| see [article number](#article-number---outdated)  --> delete ❗ | -|
|Device role (primary)  | DeviceRole:name          | core| used for characterization and future features |see [Device Roles](https://netboxlabs.com/docs/netbox/en/stable/models/dcim/devicerole/) |
|Device role (secondary)| DeviceRole:name_minor    | custom| used for characterization and future features |see [Device Roles](https://netboxlabs.com/docs/netbox/en/stable/models/dcim/devicerole/) |
|Manufacturer           | Manufacturer:name        | core| manufacturer **of device type**| ABB, Schneider Electric|
|Device Type Name       | manufacturer + model     | N/A| used for assign a device to a device type.| [Details](#device-family) |
|Device Family          | DeviceType:device_family | custom /❗[Device Type](#discussion-device-type) | usually family a model is assigned to | [DeviceType](https://netboxlabs.com/docs/netbox/en/stable/models/dcim/devicetype/)|
|Model_number           | DeviceType:model  | core/❗[Device Type](#discussion-device-type) | Model number given by the manufacturer. One specification of a device_family | 6RA8096-4MV62-0AA0 [Details](#model-number) |
|SKU                    | DeviceType:part_number   | core/❗[Device Type](#discussion-device-type) | SKU (stock keeping unit) also known as part number | [Details](#part-number) |
|Device Description     | DeviceType:device_description | custom/❗[Device Type](#discussion-device-type) | additional, optional field for detailed device description| [Device Description](#device-description)|
|Hardware Name           |DeviceType:hardware_name  | :hammer:modify/custom/❗[Device Type](#discussion-device-type)  |HW  of device, not of installed software (flag must be set in Netbox) | -|
|Hardware version        |DeviceType:hardware_version | :hammer:new/custom/❗[Device Type](#discussion-device-type) | Hardware version of the product; use "N/A" if just one version was build; use "unknown" if not known. The notations of the manufacturer should not be altered. | see Software version |
|Software Manufacturer    |Software:manufacturer | :hammer: new :hammer: | distinguish between manufacturer of the device | |
|Firmware Name           |Software:name       | custom  |FW of device, not of installed software (flag must be set in Netbox) | -|
|Firmware Version        |Software:version    | :hammer: modify :hammer:  | FW version of device, not of installed software (flag must be set in Netbox). | see Software version |
|Serial  Number         | Device:serial            | core | specific serial number of device | -|
|Communication partner - IP| Communication:dst_ip_addr | core | not observed CP but expected one (source of truth) for IDS | - |
|Communication partner - Protocol| Communication:transport_protocol| core | not observed CP but expected one (source of truth) |-|
|Software Name           |Software:name       | custom   |The name this particular version is given| - |
|Software Version        |[Software:version](#version-number)    | :hammer: modify :hammer: | :information_source: There are plenty of valid notations for version schema. Therefore, there is no common standard. | MAYOR.MINOR.PATCH.BUILD or YEAR-MONTH-DATE or hash value |
|Safety                  |Device:safety      | custom | device is used for safety functionality. Information also in CVSS available. |-|
|Exposure                |Device:Exposure    | custom | exposure to other networks| see [exposure](#exposure)|
|CPE                     |DeviceType:cpe     | custom | Common Platform Enumeration (CPE), is also used as CSAF product identification helper|[CSAF-Standard 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#31331-full-product-name-type---product-identification-helper---cpe)|
|Hashes                  |Software:Hashes    | custom | for firmware and applications software, is also used as CSAF product identification helper |[CSAF-Standard 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#31332-full-product-name-type---product-identification-helper---hashes)|
|purl                    |Software:Hashes    | custom | package URL (purl), is also used as CSAF product identification helper | [CSAF-Standard 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#31334-full-product-name-type---product-identification-helper---purl)|
|SBOM_URLs               |Software:sbom_urls | custom | The URL is a unique identifier. The content is secondary| [CSAF-Standard 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#31335-full-product-name-type---product-identification-helper---sbom-urls)|
|x_generic_uris          |Software:x_generic_uris AND DeviceType:x_generic_uris| custom |unique id given by the vendor (e.g. [#649](https://github.com/oasis-tcs/csaf/issues/649))| [CSAF-Standard 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#31338-full-product-name-type---product-identification-helper---generic-uris)|
|Age                     |Device:year     | :hammer: new :hammer: | Year of construction of the device| 2018|
|Inventory Number | Device:Inventory_number | :hammer: new :hammer: |  Not relevant for vulnerability matching. However, for linking the dataset to other internal products like SAP | - |

## Further Description

### Article Number - outdated

Text field is currently added to the Device Type object. Specifies the stock keeping unit (SKU).  It can be the same as model number (NetBox: part\_number), especially when seller is the vendor itself.

### Communication partner - IP

not observed communication partner IP but expected one (source of state)

### Communication partner - Protocol

not observed communication partner protocol but expected one (source of state)

### CPE

Text field added to the Device Type object. Specifies the Common Platform Enumeration (CPE) string of the device type.

### Device Status

Values are a specified enumeration already present in NetBox.

### Exposure

Selection added to the Device Type object. Specifies the grade of exposure to other networks. Valid values are:

- Small:  The asset is in a highly isolated and controlled zone. There are no connections from this cyber asset’s zone to or from a zone with lower trust.
- Indirect: The asset has no direct access to a zone with lower trust, but other cyber assets in this cyber asset’s zone are accessible to or from a zone with lower trust.
- Direct: The asset is directly accessible to or from a zone with lower trust.
- Unknown: Value if category for exposure is unknown.  

### Is Router

Selection added to the Interface object. Specifies whether one of the device's interfaces is a router interface or not. Valid values are:

- Yes: Yes, if it is a router interface.
- No: No, if it is not a router interface.
- Maybe: Maybe, if it might be a router interface.
- Unknown:  Value if category is unknown.

### Manufacturer Name

Legally valid designation of the natural or judicial body which is directly responsible for the design, production, packaging
and labeling of a product in respect to its being brought into the market.\[[IDTA 02003 1 2]\](#idta-02003-1-2)

In DINA it is used in the plugin under software and as core input of the device type in Netbox.

### Safety

Boolean field added to the Device object. Specifies, if the device is used/provides safety functionality.

### Secondary Roles

Multiple objects field added to the Device object. It should be possible to assign multiple Device Roles to a device. Therefore, this custom field enables the user to designate multiple Device Roles for a device using this feature. Additionally, the existing 'Role' attribute of a device should be understood as the primary role of the device.

### Serial Number

unique combination of numbers and letters used to identify the device once it has been manufactured. [IDTA 2006](#idta-02006-2-0)

Helps to determine the affectedness. For example, a batch (SN range) has been shipped with a FW that contains a vulnerability.

### Software Name

Examples: OS like Linux or libraries in python.

### Software Type

It has to be distinguished between firmware and additional software by the flag "is firmware".

### version number

:information_source: There are plenty of valid notations for version schema. Therefore, there is no common standard.

#### version number - AAS

```text
The complete version information consisting of Major Version, Minor Version, Revision and Build Number
```

#### version-number - CSAF

CSAF provides two attributes for version information:

- product_version
- product_version_range

In the latter case, it is recommanded to use the version range specifier [vers](https://github.com/package-url/purl-spec/blob/version-range-spec/VERSION-RANGE-SPEC.rst).

#### version-number - DINA

There are plenty of valid notations for version schema. Therefore, there is no common standard

### x_generic_uris

Unique name given by the vendor. The TC provides some [examples](https://github.com/oasis-tcs/csaf/issues/649). Hardware and software, can have one or more x_generic_uri. However, an x_generic_uri can only belong to one hardware resp. software.

### Year of Construct

This information might be relevant for legacy products when mapping against new information where the product is renamed or listed under a new vendor.

## Discussion Device Type

The problem with the core field in Netbox for Device Type is that the model is unique and also the full identification for the device type. This leads to problems, when describing a device with [CSAF](https://csaf.io), since there is more than just a model (name) such as product family, product name and a stock keeping unit (sku) as illustrated with the following example:

| attribute | Netbox | DDDC |
|:---:|:----:|:---:|
| manufacturer | Rockwell Automation| Rockwell Automation|
| family | N/A | ControlLogix |
| model (number) | ControlLogix Rack K - 10 Slot| Rack K -10 Slot|
| part_number | 1756-A10K | 1756-A10K (sku)|
| | | |

In the following, some solutions for this problem is addressed

- [Enhance the deviceType describtion](#approach-1-model-name)
- [Make the deviceType recursiv](#approach-2-recursiv-devicetypes)

## Approach 1 Model Name

The model name is not important for mapping assets to CSAF documents, but to assign devices correctly in Netbox. Therefore, the proposal for the [Data model device Type #14125](https://github.com/netbox-community/netbox/discussions/14125) was made. It should be the sum of

- [device family](#device-family)
- [model number](#model-number)
- [part number](#part-number)
- [hardware version](#hardware-version)

### Device Family

#### device family Netbox

Not available. It is a part of the model name.

#### device family DINA

Text field added to the Device Type object. Specifies the family of a model (device type) (e.g. SIMATIC, SCALANCE) is assigned to.

### model number

#### model number Netbox

In Netbox the name convention is a little bit misleading, since under [devicetype-library](https://github.com/netbox-community/devicetype-library) a `model` is defined as :

```text
The model number of the device type. This must be unique per manufacturer.
```

So the object `model` is the model name as well as model number.

#### model number DINA

A model number can be used as an article number. However, an article number is not always/necessarily a model number. Usually, all products have model numbers, often they are listed on the sticker on the device besides the serial number

#### model number CSAF

```text
The terms "model", "model number" and "model variant" are mostly used synonymously. Often it is abbreviated as "MN", M/N" or "model no.".
```

### part number

#### Netbox part number

```text
An alternative representation of the model number (e.g. a SKU). 
```

#### part number - CSAF

CSAF defines the product identification helper [SKU](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#31337-full-product-name-type---product-identification-helper---skus):

```text
Any given stock keeping unit of value type string with at least 1 character represents a full or abbreviated (partial) stock keeping unit (SKU) of the component to identify. Sometimes this is also called "item number", "article number" or "product number".
```

#### part number - DINA

It can be the same as model_number, especially when seller is the vendor itself. This can be used as an alternative presentation of the model number [e.g. SKU as in devicetype-library](https://github.com/netbox-community/devicetype-library).

### Device Description

Text field added to the Device Type object. Intended as an additional reminder alongside the device type name (e.g. CPU 414-3 PN/DP central unit with 4 MB RAM...). Could be partially part of full_product_name_t/name in a CSAF document.

### Hardware Version

Text field added to the Device Type object. Specifies the hardware version of the device type. Hardware version can be “N/A” if just one version was build. Multiple products exist in multiple hardware versions (due to PCB layout changes or chip shortages or hardware improvements), which can have impact on the software that can be used with the device.

## Approach 2 Recursiv DeviceTypes

There is an additional problem: manufacturers do not have a common level of the product hierarchy. This might also be the reason why level 2 is not clearly described in the IDTA.

Instead of extending the DeviceType classification, the current design of a DeviceType should remain unchanged. Only one additional field would be required:

- Is the DeviceType a child of another DeviceType?

In this way, the variable depth of manufacturers' product descriptions can be displayed.

```plaintext
Manufacturer
├── product family A
│   └── product of family A
│       ├── further specification
│       │   └── final specification (part number)
│       └── further specification
│           └── ...
├── product family B
    └── product of family B
        ├── further specification
        │   └── ...
        └── further specification
            └── final specification (part number) 
```

Always use the model name for the description of model, submodel or specification. In that way

- 1st model name describes the product family,
- 2nd model name can be used to differentiate between different products of this family,
- 3th model name can be used to differentiate between different specifications or sub products of this product.

In addition, the part number can also include the hardware version. This makes an additional custom field obsolete.
