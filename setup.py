from setuptools import setup

with open("README.md", 'r') as fh:
	long_description = fh.read()


setup(

	classifiers=[
		"Programming Language :: Python :: 3",
		"Programming Language :: Python :: 3.6",
		"Programming Language :: Python :: 3.7",
		"License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)",
		"Operating System :: OS Independent",
		"Natural Language :: English",
		"Topic :: Internet"
		"Topic :: Internet :: Proxy Servers"

	],

	install_requires = [
		"certifi==2022.6.15",
		"idna==3.3",
		"netifaces==0.11.0",
		"requests==2.28.1",
		"urllib3==1.26.10"
	],
	url = "https://github.com/makiisthenes/Proxy5Server",
	author="Michael Peres",
	author_email="michaelperes1@gmail.com",
	name = "makiproxy5",
	version="0.0.1",
	description="A socks 5 proxy server written in Python, class based.",
	py_modules=["maki_proxy"],
	package_dir={'': 'src'},
	long_description = long_description,
	long_description_content_type="text/markdown",
	)