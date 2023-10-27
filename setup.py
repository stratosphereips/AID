import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aid_hash",
    version="1",
    author="Christian Kreibich, Alya Gomaa",
    author_email="christian@corelight.com, alyaggomaa@gmail.com",
    description="All-ID flow hashing; a community_id implementation that supports timestamps",
    license="BSD",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/stratosphereips/AID",
    packages=['aid_hash'],
    scripts=['scripts/all_id.py'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
)
