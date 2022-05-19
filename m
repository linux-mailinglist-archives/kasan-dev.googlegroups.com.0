Return-Path: <kasan-dev+bncBC6OLHHDVUOBBGUITGKAMGQECB53QVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id BDD0752D3C9
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 15:20:26 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id oz9-20020a1709077d8900b006f3d9488090sf2531583ejc.6
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 06:20:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652966426; cv=pass;
        d=google.com; s=arc-20160816;
        b=sqzA+lukh3S3lQ+C7NBTWDjAYpMCJHr0w2Mvno0wgZuaalofO8CGEulzRs5Mu7w+2g
         mn4x/QHiXQ/eTGe3dh9Y6VBQS4MctKrSMvRMZG4EbQPANOY+uSJYyxp8njYjON0qx07w
         bJlZ3oJc41q67eqqSImMtiFVPhImrL9V2CX+cgL0Q6nfbO8se56lwSkeQe3U/ZA4m6h7
         rBb5wbAvirx/fFiPqoppaihW5gtM+o46u7ZT1O1J2x8QKjLUlmwfTJ+svc6rm+vuEDeo
         PZ4J9iEdhUM+l31njhUnxlLRXzI4X7tSplmF2NicYVu/trbQMbZoSkf3hpVKXyXYqx1A
         cA5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rK0qZ5aR2/+DcK5LIL0tRWXcqooiEqkYxgIU8p3w4Ww=;
        b=pr+jcedWYGvnuYLsa5T48mZxtZ831nJZRK6AJtoU9aM6R5n9NIT2sUktHSN3lJV5c0
         oYUmnM6Oph9mGETq8P6OjrkMXUOninnDA+lR/OJgd1ztfuEvnl5+Rl3/AQHj/QV2LEO6
         zvAotxs3JyItISuwm9bysfloThjd2lVnl3TP4o+/R9dt5X96OBRyh15eqyTlNNzfrCM7
         0+NgLP42EeWsS6culq1iqzEP3SKxOjSrFOBEmJzhGE+E9rLShmbeqbbLLwqHpHNhRKRQ
         W07u9Go4BKSkJIaZVRZT62+RMqr7aeAjq1fT7rwo43DS3QnSENI8AhAR/Yg2FWhSCDS5
         qxow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QXgNLNcZ;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rK0qZ5aR2/+DcK5LIL0tRWXcqooiEqkYxgIU8p3w4Ww=;
        b=axVMPaZFsgTo6Et0PUWdRB4benkmxfCiRwa6k2lTcEr0vWH4cObIBxNhfChIf8ibPt
         bFKuixlBv13sRxfLeCO2+2meQOQKtV5VKDkmwdB2AcGRebsQbzsH0ZjWRx6iveGsyDT0
         XLxzXom1H4FlkahKDn+FStVjAzQJjLuJ9N6tbGGFAP6L2ykA8XRYz5XRcR58ebBDooJQ
         jK7FkUAPKuNUDRyC7osKdrHPGm4WSonuAtHcTjzw+3CFjODLjtienOXOOYSw1TZ/zBWC
         C3mLZ1oQlUAQ9eUkFbHAFUoDn7LazUxAJA9nvQrANjReREB5OPXDaq7Vl4WBI3XPEewA
         vqGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rK0qZ5aR2/+DcK5LIL0tRWXcqooiEqkYxgIU8p3w4Ww=;
        b=GHQkQd+RYGH1/QVjQK8s4OC/pb70iDuFOFNdymsu2/81No4oF4nrng6e8g7v7Kxd+x
         i3rPgTlsD6DOfww8Rv3FvD2xqTAkgpjmO7eC0lXL5Qcoj+J85aeP9SXerj2GNnuvK212
         zBUy6ThHClU7m5SQTmi8l27aLd2pDibPg0DUWFvOd+EiFGZo8xadHPEHj/ejrgAtEQeg
         D/AMYr4heUTJzUeTh2bDFOJw+zhXmTI1IHmenFZYxoPW8bLbhOA4Ervk1pnvoDNJenkn
         VLIUzDl81fATIcYCovzTyIKhMZS/Ri93I86MyLpfrBLNaaHoc97wfPs+5sh8Ezo3rY4e
         kl3A==
X-Gm-Message-State: AOAM5317+C1ckiIIuqZo5d0bvBlPQnHVEIWQ9AzZH4AO194u4jtbi+uX
	NS2S9F99Dr357feNLpjkryU=
X-Google-Smtp-Source: ABdhPJxPWEj0nTcAzu6sLFvTc69SOj1Yhv/BYgwYVyT7WH+ha4aC/k42hkLydtTu7QFal5RKDv4LCA==
X-Received: by 2002:a17:907:3e25:b0:6fe:526a:a663 with SMTP id hp37-20020a1709073e2500b006fe526aa663mr4298016ejc.626.1652966426240;
        Thu, 19 May 2022 06:20:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6e09:b0:6f3:ead4:abc6 with SMTP id
 sd9-20020a1709076e0900b006f3ead4abc6ls899215ejc.5.gmail; Thu, 19 May 2022
 06:20:24 -0700 (PDT)
X-Received: by 2002:a17:907:a428:b0:6fa:9253:6f88 with SMTP id sg40-20020a170907a42800b006fa92536f88mr4502225ejc.518.1652966424888;
        Thu, 19 May 2022 06:20:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652966424; cv=none;
        d=google.com; s=arc-20160816;
        b=In47dKJw4RuyhHBtrVpe9Y4AEIETCWDSbErKzTlWMEaRhF2oaVoTAoXadUd5010HtO
         mH8WUl0u4WWDf6rqUipppsXE8qhpozSlk5tnlojUF+BVbIzbAznpXbJf8Zed3Q5NW2pZ
         gvym78aceaQq41/yqzJAS90yHzW+oc3K9XhS9ixxMBCsvpJyMG15j+Uvo6pDFep1RBXr
         peH6KiLf7rJ8sR3uYWWR6Xsc++u+++4t0OBnE0ckpH1WQtB/bqUfIK7aEbhpDIMffCHa
         iElu0Fn2aiOwPEvj6HHUxyG55U2z/IBtl+0x9PBC0snSmKhcTLvo0kl5AfU8GZUfNKHD
         w0kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NffP4SVy5kSeDJ+aaMgcmyRppTrzDhfoTGBAX/Tl7Xk=;
        b=1EMowZQLJ8hOUIF+228VadLh+MtJoQgpCrHDIjwm1NL+R/rvL7pq3P+GJrxUPUFOrU
         CyCi/g2X2r8hMpYfEO0mZZwA/25hyza8dsfGkH48WNSiKqJMUqvJ3OXkXPHL9on8d3Gs
         /oyZ8Qf03piSPQjzspN4hHB1HiGu14Wu78ZqDhT40u0LcBLCrT0ueLIn4mA25lODueej
         BAEBXSMtEHunRY/hVrsAm0iHyIniEIO31bGzfE0TnVImn58Ra757eTQlw0iE3FDyqnX7
         3NkAMWUo4z/ujZv3DyHfPDxlvjIyGgnFLRAywz6fIKm1FnsBmrksfb7EeNld4AChCpDw
         PkjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QXgNLNcZ;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id d10-20020a50cd4a000000b00418d53b44b8si303888edj.0.2022.05.19.06.20.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 May 2022 06:20:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id bd25-20020a05600c1f1900b0039485220e16so3768973wmb.0
        for <kasan-dev@googlegroups.com>; Thu, 19 May 2022 06:20:24 -0700 (PDT)
X-Received: by 2002:a05:600c:1f08:b0:394:9060:bb54 with SMTP id
 bd8-20020a05600c1f0800b003949060bb54mr3859375wmb.73.1652966424279; Thu, 19
 May 2022 06:20:24 -0700 (PDT)
MIME-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com> <20220518170124.2849497-4-dlatypov@google.com>
In-Reply-To: <20220518170124.2849497-4-dlatypov@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 May 2022 21:20:12 +0800
Message-ID: <CABVgOSkTc08s=0Ai=utBv2UpM48M--b64xJGC=Gj8PCZ9yJ1_Q@mail.gmail.com>
Subject: Re: [PATCH 3/3] kunit: tool: introduce --qemu_args
To: Daniel Latypov <dlatypov@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Marco Elver <elver@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000938e2405df5d3cb0"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QXgNLNcZ;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::32e
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

--000000000000938e2405df5d3cb0
Content-Type: text/plain; charset="UTF-8"

On Thu, May 19, 2022 at 1:01 AM Daniel Latypov <dlatypov@google.com> wrote:
>
> Example usage:
> $ ./tools/testing/kunit/kunit.py run --arch=x86_64 \
>   --kconfig_add=CONFIG_SMP=y --qemu_args='-smp 8'
>
> Looking in the test.log, one can see
> > smp: Bringing up secondary CPUs ...
> > .... node  #0, CPUs:      #1 #2 #3 #4 #5 #6 #7
> > smp: Brought up 1 node, 8 CPUs
>
> This flag would allow people to make tweaks like this without having to
> create custom qemu_config files.
>
> For consistency with --kernel_args, we allow users to repeat this
> argument, e.g. you can tack on a --qemu_args='-m 2048', or you could
> just append it to the first string ('-smp 8 -m 2048').
>
> Signed-off-by: Daniel Latypov <dlatypov@google.com>
> ---

I like this -- it's definitely something I've wanted to have in the
past. I was a bit worried about how we'd handle longer strings of
arguments, but the combination of the shlex-based splitting and
repeated arguments seems to work for all the cases I can think of.
(And it's much nicer than, e.g, passing linker flags with -Wl,a,b,c in
my opinion!)

Reviewed-by: David Gow <davidgow@google.com>


-- David

>  tools/testing/kunit/kunit.py           | 14 +++++++++++++-
>  tools/testing/kunit/kunit_kernel.py    | 10 +++++++---
>  tools/testing/kunit/kunit_tool_test.py | 20 +++++++++++++++++---
>  3 files changed, 37 insertions(+), 7 deletions(-)
>
> diff --git a/tools/testing/kunit/kunit.py b/tools/testing/kunit/kunit.py
> index 8a90d80ee66e..e01c7964f744 100755
> --- a/tools/testing/kunit/kunit.py
> +++ b/tools/testing/kunit/kunit.py
> @@ -10,6 +10,7 @@
>  import argparse
>  import os
>  import re
> +import shlex
>  import sys
>  import time
>
> @@ -323,6 +324,10 @@ def add_common_opts(parser) -> None:
>                                   'a QemuArchParams object.'),
>                             type=str, metavar='FILE')
>
> +       parser.add_argument('--qemu_args',
> +                           help='Additional QEMU arguments, e.g. "-smp 8"',
> +                           action='append', metavar='')
> +
>  def add_build_opts(parser) -> None:
>         parser.add_argument('--jobs',
>                             help='As in the make command, "Specifies  the number of '
> @@ -368,12 +373,19 @@ def add_parse_opts(parser) -> None:
>
>  def tree_from_args(cli_args: argparse.Namespace) -> kunit_kernel.LinuxSourceTree:
>         """Returns a LinuxSourceTree based on the user's arguments."""
> +       # Allow users to specify multiple arguments in one string, e.g. '-smp 8'
> +       qemu_args: List[str] = []
> +       if cli_args.qemu_args:
> +               for arg in cli_args.qemu_args:
> +                       qemu_args.extend(shlex.split(arg))
> +
>         return kunit_kernel.LinuxSourceTree(cli_args.build_dir,
>                         kunitconfig_path=cli_args.kunitconfig,
>                         kconfig_add=cli_args.kconfig_add,
>                         arch=cli_args.arch,
>                         cross_compile=cli_args.cross_compile,
> -                       qemu_config_path=cli_args.qemu_config)
> +                       qemu_config_path=cli_args.qemu_config,
> +                       extra_qemu_args=qemu_args)
>
>
>  def main(argv):
> diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
> index e93f07ac0af1..a791073d25f9 100644
> --- a/tools/testing/kunit/kunit_kernel.py
> +++ b/tools/testing/kunit/kunit_kernel.py
> @@ -187,6 +187,7 @@ def _default_qemu_config_path(arch: str) -> str:
>         raise ConfigError(arch + ' is not a valid arch, options are ' + str(sorted(options)))
>
>  def _get_qemu_ops(config_path: str,
> +                 extra_qemu_args: Optional[List[str]],
>                   cross_compile: Optional[str]) -> Tuple[str, LinuxSourceTreeOperations]:
>         # The module name/path has very little to do with where the actual file
>         # exists (I learned this through experimentation and could not find it
> @@ -207,6 +208,8 @@ def _get_qemu_ops(config_path: str,
>         if not hasattr(config, 'QEMU_ARCH'):
>                 raise ValueError('qemu_config module missing "QEMU_ARCH": ' + config_path)
>         params: qemu_config.QemuArchParams = config.QEMU_ARCH  # type: ignore
> +       if extra_qemu_args:
> +               params.extra_qemu_params.extend(extra_qemu_args)
>         return params.linux_arch, LinuxSourceTreeOperationsQemu(
>                         params, cross_compile=cross_compile)
>
> @@ -220,17 +223,18 @@ class LinuxSourceTree:
>               kconfig_add: Optional[List[str]]=None,
>               arch=None,
>               cross_compile=None,
> -             qemu_config_path=None) -> None:
> +             qemu_config_path=None,
> +             extra_qemu_args=None) -> None:
>                 signal.signal(signal.SIGINT, self.signal_handler)
>                 if qemu_config_path:
> -                       self._arch, self._ops = _get_qemu_ops(qemu_config_path, cross_compile)
> +                       self._arch, self._ops = _get_qemu_ops(qemu_config_path, extra_qemu_args, cross_compile)
>                 else:
>                         self._arch = 'um' if arch is None else arch
>                         if self._arch == 'um':
>                                 self._ops = LinuxSourceTreeOperationsUml(cross_compile=cross_compile)
>                         else:
>                                 qemu_config_path = _default_qemu_config_path(self._arch)
> -                               _, self._ops = _get_qemu_ops(qemu_config_path, cross_compile)
> +                               _, self._ops = _get_qemu_ops(qemu_config_path, extra_qemu_args, cross_compile)
>
>                 if kunitconfig_path:
>                         if os.path.isdir(kunitconfig_path):
> diff --git a/tools/testing/kunit/kunit_tool_test.py b/tools/testing/kunit/kunit_tool_test.py
> index baee11d96474..7fe5c8b0fb57 100755
> --- a/tools/testing/kunit/kunit_tool_test.py
> +++ b/tools/testing/kunit/kunit_tool_test.py
> @@ -649,7 +649,8 @@ class KUnitMainTest(unittest.TestCase):
>                                                 kconfig_add=None,
>                                                 arch='um',
>                                                 cross_compile=None,
> -                                               qemu_config_path=None)
> +                                               qemu_config_path=None,
> +                                               extra_qemu_args=[])
>
>         def test_config_kunitconfig(self):
>                 kunit.main(['config', '--kunitconfig=mykunitconfig'])
> @@ -659,7 +660,8 @@ class KUnitMainTest(unittest.TestCase):
>                                                 kconfig_add=None,
>                                                 arch='um',
>                                                 cross_compile=None,
> -                                               qemu_config_path=None)
> +                                               qemu_config_path=None,
> +                                               extra_qemu_args=[])
>
>         def test_run_kconfig_add(self):
>                 kunit.main(['run', '--kconfig_add=CONFIG_KASAN=y', '--kconfig_add=CONFIG_KCSAN=y'])
> @@ -669,7 +671,19 @@ class KUnitMainTest(unittest.TestCase):
>                                                 kconfig_add=['CONFIG_KASAN=y', 'CONFIG_KCSAN=y'],
>                                                 arch='um',
>                                                 cross_compile=None,
> -                                               qemu_config_path=None)
> +                                               qemu_config_path=None,
> +                                               extra_qemu_args=[])
> +
> +       def test_run_qemu_args(self):
> +               kunit.main(['run', '--arch=x86_64', '--qemu_args', '-m 2048'])
> +               # Just verify that we parsed and initialized it correctly here.
> +               self.mock_linux_init.assert_called_once_with('.kunit',
> +                                               kunitconfig_path=None,
> +                                               kconfig_add=None,
> +                                               arch='x86_64',
> +                                               cross_compile=None,
> +                                               qemu_config_path=None,
> +                                               extra_qemu_args=['-m', '2048'])
>
>         def test_run_kernel_args(self):
>                 kunit.main(['run', '--kernel_args=a=1', '--kernel_args=b=2'])
> --
> 2.36.1.124.g0e6072fb45-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkTc08s%3D0Ai%3DutBv2UpM48M--b64xJGC%3DGj8PCZ9yJ1_Q%40mail.gmail.com.

--000000000000938e2405df5d3cb0
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIPnwYJKoZIhvcNAQcCoIIPkDCCD4wCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ggz5MIIEtjCCA56gAwIBAgIQeAMYYHb81ngUVR0WyMTzqzANBgkqhkiG9w0BAQsFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMDA3MjgwMDAwMDBaFw0yOTAzMTgwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFIzIFNNSU1FIENBIDIwMjAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvLe9xPU9W
dpiHLAvX7kFnaFZPuJLey7LYaMO8P/xSngB9IN73mVc7YiLov12Fekdtn5kL8PjmDBEvTYmWsuQS
6VBo3vdlqqXZ0M9eMkjcKqijrmDRleudEoPDzTumwQ18VB/3I+vbN039HIaRQ5x+NHGiPHVfk6Rx
c6KAbYceyeqqfuJEcq23vhTdium/Bf5hHqYUhuJwnBQ+dAUcFndUKMJrth6lHeoifkbw2bv81zxJ
I9cvIy516+oUekqiSFGfzAqByv41OrgLV4fLGCDH3yRh1tj7EtV3l2TngqtrDLUs5R+sWIItPa/4
AJXB1Q3nGNl2tNjVpcSn0uJ7aFPbAgMBAAGjggGKMIIBhjAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0l
BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHzM
CmjXouseLHIb0c1dlW+N+/JjMB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHsGCCsG
AQUFBwEBBG8wbTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3Ry
MzA7BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvcm9vdC1y
My5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIz
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
G7p3AiuB2sgfq6cOpbO5MEwGA1UdIARFMEMwQQYJKwYBBAGgMgEoMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZoGCCsG
AQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
c2F0bGFzcjNzbWltZWNhMjAyMDBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
LmNvbS9jYWNlcnQvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3J0MB8GA1UdIwQYMBaAFHzMCmjXouse
LHIb0c1dlW+N+/JjMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Y2EvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQBsL34EJkCtu9Nu
2+R6l1Qzno5Gl+N2Cm6/YLujukDGYa1JW27txXiilR9dGP7yl60HYyG2Exd5i6fiLDlaNEw0SqzE
dw9ZSIak3Qvm2UybR8zcnB0deCUiwahqh7ZncEPlhnPpB08ETEUtwBEqCEnndNEkIN67yz4kniCZ
jZstNF/BUnI3864fATiXSbnNqBwlJS3YkoaCTpbI9qNTrf5VIvnbryT69xJ6f25yfmxrXNJJe5OG
ncB34Cwnb7xQyk+uRLZ465yUBkbjk9pC/yamL0O7SOGYUclrQl2c5zzGuVBD84YcQGDOK6gSPj6w
QuBfOooZPOyZZZ8AMih7J980MYICajCCAmYCAQEwaDBUMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAxMhR2xvYmFsU2lnbiBBdGxhcyBSMyBTTUlNRSBDQSAy
MDIwAhABQeVybOOpR4bOOXZYL5T3MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCBE
l8eGuobgbxdCXiWAycy3h0d/f9+NM+9vSaZi/bkNdzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA1MTkxMzIwMjRaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAcovz9H1vfWX6ORKauN2N
3Bor/je/s0QqpHbV90DL988XL69myUtmlOs8A2pK+nPWL1Ig25RBclQuHxe+ypgo8sjNYexO1aDn
VDBYGwSgLWrcjXR3Ja4E8nBAYpqUgZi9qvtJEZCTj5oragrRE5CsnmPPM7pdEQmu/evZcTeuCYd8
NfS6x7PI8ORWc+e7if+eVdvYQgjdhCCrbLwjNsG2sGR/9xHgycfbP/w5uCwpoB0Yuu1T3gXiztHE
oNpIslenqVaV6wSizunmc++n9w1FNzbayrcx8ACB41eOcNRfTnA3+wy/3LGg+YYnY8AYKvp/i8YO
dlKEqt1Q8ELKzQFxFQ==
--000000000000938e2405df5d3cb0--
