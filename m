Return-Path: <kasan-dev+bncBC6OLHHDVUOBBFEITGKAMGQEHBEXFHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3842052D3C7
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 15:20:21 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id u13-20020a05651206cd00b00477c7503103sf1075298lff.15
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 06:20:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652966420; cv=pass;
        d=google.com; s=arc-20160816;
        b=BOXTVNdn6j2kD8lsNqVGZgT0ffrLlnk1KGmIwm/sOph1JlDjwSw9QTdocnTxWQXoyw
         sKJbNyQRJ2Ah6Ys/4z6opFm3ShnQQt/xP9PsypS59qVii8wVCYWK+M6xsVx8y1qpfL/2
         AxU6OljXJ+6VHyeew4mz4SDaAVpCTBmYZS80V0pAvzR/rpNbPqWpANHQPKHrg7PY6ZGY
         6B+38czEDfAEkDtCN4tFlGeyzvkqYHtBrPHghas9NN6+BkAfSYBSW54v/I59A2W0U0Xk
         fqzVLUiuvl0Y3lkBtliKc7XoSZn183EzEP0H3aSMOCoO+R477SQzYO5Z6V/DRQSKEwTt
         BNjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UbLQ8AA/lQuiS7iVNr1w1q1PXNgyfVozCwJKtXYXfog=;
        b=oKHR+5o7u3fl+wKIIfZkhHKeSbTalE0Et+YKNdcXafny1Nei4AiCfa4T8xwm1RGjLm
         RG2U03BMjDUrAHLnazUiAyoFHQ07HoWqVKTrkp21aaX5Vv526Ey7lC8lmFQnrK7zDHPL
         dlEap/FRxB4haVsQfxWS8hvK7X/FMhya3sIbk1Jztjz3Vt599r2cluSkiXMXBcc9LfQC
         elXxv2GRXFZCKDACiSelNb/keR1IBy2wO/LEh5r2wkErKGvBOv0/oCBzv8R0wsjJ+9zf
         Kx9ei//IQVRYWglTVeGy8IPkQox/D4nbNqP8fMtw6Ote967lucEsXIaNQqpz5Pbnabla
         WHBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VpEic86E;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UbLQ8AA/lQuiS7iVNr1w1q1PXNgyfVozCwJKtXYXfog=;
        b=IVBDVrYh74jZSGF50Sk0MVl88thcnGw36AcjoHLUR1/Cg9LyliPLn071OrXZCMqwMx
         t0FDoJ5meT7hPBIqOsAkf3Dq3kM/p+b4XSqSY/k7w6WViJ3hvCEZlDgYwTc9Z+pL8Ww/
         EdMAvuwoCxDrC0yVuNkhDxVIS02i8IOkU+nuez+Y0vKLLV0V8joSarHOPs56RwRJzEeC
         PCj2jW/SKSuZkie4OqP+xwUqkOaTv0DuasHcXS7ta01dIvH9aotsG11Q+4yLyaQ0w3qm
         1EIB4mFi9aqgDj2THrNWUVhACKn2B0eS/k6h5pb2lnVffsTz6TOgyX+mwqVYBD0257mB
         iZtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UbLQ8AA/lQuiS7iVNr1w1q1PXNgyfVozCwJKtXYXfog=;
        b=JbYiBEZa0JXWGbtlN4TWamN44Yw+CFGRRmJ4YMZvypMHXOL0MN9GKa7Z8BX6GMENTL
         FRThtyCPonV0DBtoWQ19G1hSpiJZDCRsOC54uFZfS1TDr4dt5/Xa7QdjB49tUAiHSQwe
         EEm8wxtQC5g5z3IntaeN20VsE5hZwE2KCqlsqz7eOd+RR0lW+Al8Yq7cMNNijhMHwcuM
         2AlVRTAVUEERWavcwR9UgEKJ4ApkCAP5fgLbUpuG5i8g/9h8yCBgmVI1nziZEkjdpb/q
         QSRRbVQQrFSUtJBbx15qH5MNFtZWonQxZ3WkMKAUTvojUny/wRgCheRaFznoylOcBrRl
         3TCA==
X-Gm-Message-State: AOAM532+PO18AcZzuMPWSr8X9bE5A2bsITzYuEBdj9CzVCkIIgFVw2wo
	r7fJBc+lFX5sDxC42dVNhTs=
X-Google-Smtp-Source: ABdhPJxyiDcQG7HKpDyvGsC1q61Fo8lA/kX/Z0T84Okww/UVQQIaKHYD4qaCTB7PmfhK0WPeMmwNnA==
X-Received: by 2002:a05:6512:280e:b0:473:a0c9:5bdf with SMTP id cf14-20020a056512280e00b00473a0c95bdfmr3300620lfb.337.1652966420654;
        Thu, 19 May 2022 06:20:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:210e:b0:250:5bd1:6dab with SMTP id
 a14-20020a05651c210e00b002505bd16dabls509703ljq.6.gmail; Thu, 19 May 2022
 06:20:19 -0700 (PDT)
X-Received: by 2002:a2e:7006:0:b0:253:cda3:1e72 with SMTP id l6-20020a2e7006000000b00253cda31e72mr2746782ljc.161.1652966419387;
        Thu, 19 May 2022 06:20:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652966419; cv=none;
        d=google.com; s=arc-20160816;
        b=vqLRY6S+2ghfRXoYUhSK3NPSv/7eQnZRzVO7wdthcs/13GbRPCZrF0MFkHa9bPfM3L
         GZbtOBvs+L+RA/nKUVnY1QPrLP55FSlqzAVGDkzTAXElE+j+QoSnnUz3gts1HR9gBC8B
         LV0vYy2bIXlHnr3xj/wIwpgcrDE1fQxMw4ehi09mhdtov0bYiWSHihYRTSdLXggzt5dV
         vv4nIKyDGVCxtzF5+mv1DWLPgu90LlFBhp/JOWbAXroRVNyo1pTUuLqoq1YfF4dQlxI1
         mVaZRxS8WdhJqZPUrtYj3z7Hw9dER12ooXe4gOyfbyvzVlQsr1vwStsqL+N/g0n+3Zs8
         /MJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fD8qm5kUtQpX1BSPLXADK2KMPDY/21OwEg9mplFq9D8=;
        b=hhGWFSLiNKaJO7/hptu5Lfc2Wek/+EttB4ssDLa7CQvmBrF1VymHQRQh2/v8upGzME
         1xd+O2i/hhGlWe3GowwZErfLFkToRqZm2H/Fc30iwYc3Xr2SABfcMmg2iVxWWDYhYwWD
         EWW2So4hKelxjkYh7m5c0Vmr1mTj0bL2HxR5Y00GyDl2mqOkavBRbcG9S5lESEGWmp7f
         LiJTYaQ3wy7M4xqISHOcKSuZ0yXlqGUixBvXfbco+hz6ExiQvAXbbAAZHtshC3hnU+Wc
         /jEoyxi/4IcQXM7ikcZKe7BxQ0JV3oKOG3pV7R0+7dtRNgSOE7BTX5OCiCEKm5MAkD/t
         2jFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VpEic86E;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id be31-20020a05651c171f00b0024eee872899si304662ljb.0.2022.05.19.06.20.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 May 2022 06:20:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id s28so7023460wrb.7
        for <kasan-dev@googlegroups.com>; Thu, 19 May 2022 06:20:19 -0700 (PDT)
X-Received: by 2002:a5d:6041:0:b0:20d:8e4:7bb8 with SMTP id
 j1-20020a5d6041000000b0020d08e47bb8mr4018587wrt.652.1652966418564; Thu, 19
 May 2022 06:20:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com> <20220518170124.2849497-3-dlatypov@google.com>
In-Reply-To: <20220518170124.2849497-3-dlatypov@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 May 2022 21:20:07 +0800
Message-ID: <CABVgOSmgxYtA0cudjHy130gMQAYBp27C8D_i2u3Zb+Jahd1toQ@mail.gmail.com>
Subject: Re: [PATCH 2/3] kunit: tool: simplify creating LinuxSourceTreeOperations
To: Daniel Latypov <dlatypov@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Marco Elver <elver@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="0000000000003bb69f05df5d3c61"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VpEic86E;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434
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

--0000000000003bb69f05df5d3c61
Content-Type: text/plain; charset="UTF-8"

On Thu, May 19, 2022 at 1:01 AM Daniel Latypov <dlatypov@google.com> wrote:
>
> Drop get_source_tree_ops() and just call what used to be
> get_source_tree_ops_from_qemu_config() in both cases.
>
> Also rename the functions to have shorter names and add a "_" prefix to
> note they're not meant to be used outside this function.
>
> Signed-off-by: Daniel Latypov <dlatypov@google.com>
> ---

Reviewed-by: David Gow <davidgow@google.com>


-- David

>  tools/testing/kunit/kunit_kernel.py | 20 ++++++++++----------
>  1 file changed, 10 insertions(+), 10 deletions(-)
>
> diff --git a/tools/testing/kunit/kunit_kernel.py b/tools/testing/kunit/kunit_kernel.py
> index 8bc8305ba817..e93f07ac0af1 100644
> --- a/tools/testing/kunit/kunit_kernel.py
> +++ b/tools/testing/kunit/kunit_kernel.py
> @@ -178,19 +178,16 @@ def get_old_kunitconfig_path(build_dir: str) -> str:
>  def get_outfile_path(build_dir: str) -> str:
>         return os.path.join(build_dir, OUTFILE_PATH)
>
> -def get_source_tree_ops(arch: str, cross_compile: Optional[str]) -> LinuxSourceTreeOperations:
> +def _default_qemu_config_path(arch: str) -> str:
>         config_path = os.path.join(QEMU_CONFIGS_DIR, arch + '.py')
> -       if arch == 'um':
> -               return LinuxSourceTreeOperationsUml(cross_compile=cross_compile)
>         if os.path.isfile(config_path):
> -               return get_source_tree_ops_from_qemu_config(config_path, cross_compile)[1]
> +               return config_path
>
>         options = [f[:-3] for f in os.listdir(QEMU_CONFIGS_DIR) if f.endswith('.py')]
>         raise ConfigError(arch + ' is not a valid arch, options are ' + str(sorted(options)))
>
> -def get_source_tree_ops_from_qemu_config(config_path: str,
> -                                        cross_compile: Optional[str]) -> Tuple[
> -                                                        str, LinuxSourceTreeOperations]:
> +def _get_qemu_ops(config_path: str,
> +                 cross_compile: Optional[str]) -> Tuple[str, LinuxSourceTreeOperations]:
>         # The module name/path has very little to do with where the actual file
>         # exists (I learned this through experimentation and could not find it
>         # anywhere in the Python documentation).
> @@ -226,11 +223,14 @@ class LinuxSourceTree:
>               qemu_config_path=None) -> None:
>                 signal.signal(signal.SIGINT, self.signal_handler)
>                 if qemu_config_path:
> -                       self._arch, self._ops = get_source_tree_ops_from_qemu_config(
> -                                       qemu_config_path, cross_compile)
> +                       self._arch, self._ops = _get_qemu_ops(qemu_config_path, cross_compile)
>                 else:
>                         self._arch = 'um' if arch is None else arch
> -                       self._ops = get_source_tree_ops(self._arch, cross_compile)
> +                       if self._arch == 'um':
> +                               self._ops = LinuxSourceTreeOperationsUml(cross_compile=cross_compile)
> +                       else:
> +                               qemu_config_path = _default_qemu_config_path(self._arch)
> +                               _, self._ops = _get_qemu_ops(qemu_config_path, cross_compile)
>
>                 if kunitconfig_path:
>                         if os.path.isdir(kunitconfig_path):
> --
> 2.36.1.124.g0e6072fb45-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmgxYtA0cudjHy130gMQAYBp27C8D_i2u3Zb%2BJahd1toQ%40mail.gmail.com.

--0000000000003bb69f05df5d3c61
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
MDIwAhABQeVybOOpR4bOOXZYL5T3MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCCS
+4L4X841OFguBpDzYW6T3+kArPb2TgVQu00u9g6PhDAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA1MTkxMzIwMTlaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAi+fKwkMOBkX9ie7pFvMY
WbzrQkSX+xiM1XbYVLXgNmycbwnmmDKXbZH7A+y5qfg4TYAAXa6xXNNAimSUesa9ycPVfI+SoW4S
618se3HPWJb4Vl1b4Flo1P2XIhVbGKLc0gztWuQz6/2Enrzy8Sba53XIFqlZ/pDgXL+6IMOq9G0U
y4KeZHfThnpWoOwT/bOfDQs5s5JQvfMPX6q+2z0ee94SClIx5RMEUwj3fhMyUqKQ1tOXMVWw+DqF
d4xXUPZ3NzRkjBh9J+4jJIDM8y5cPu1YY5iebRplsXfw8Y0QUCr8pO4JQRNUyzGPo6IgoP/03pWC
brSHtWEfvU8/vecI9Q==
--0000000000003bb69f05df5d3c61--
