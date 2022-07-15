Return-Path: <kasan-dev+bncBC6OLHHDVUOBBCU4YSLAMGQET5FLJSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 11838575BCA
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 08:49:47 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id t13-20020adfe10d000000b0021bae3def1esf927623wrz.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 23:49:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657867786; cv=pass;
        d=google.com; s=arc-20160816;
        b=RrYozPL2sIt/2O+pxovMBvbrINzP+qeYsJq6bmGmnl5FA4M06nDn0Qp2FDwAfjLKZX
         g6urpeRH1VE+dU7qDBtw6HJ0mDa1DxNwIIe6luveufvxJxzQQJnfsTOW4mJnZrduKMA3
         M7SqWoMjs2ltfO5C8zrY+cbgee+OYcnV5zUTj65hLoREG3nmLVRka7xV7Gm8nMRuLf0X
         Z9daipxTbZ84qIaUfFeIDGuGjXJScDjJWz88pi6eRfdpmEXO4oJDQXQEYB/WEj9njT3R
         AAuHPWMjT70JYpK6qmkGYYze3nz9s8YoIeR4/l9+O4Piv4NkMQMdg7ZL1fjQEe+QOfY4
         ISLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9tcruD+UxlfLlQR4273nkYi5U/qwNoKxPjAZPusNSJM=;
        b=TixtQKxGTzABNQxYkSfJtCddoOwPl/uYWrdTuwIDcmG1E+kHMTaZe3TPcxRy7btXMu
         7lFzf6CYxO7UsuW/TgeBlD1l0962DnDFvGN7w/BESsmIrl5QyiAF4js+E26hwYeGrxaO
         ud6qAULMYU0o6DmyKTe2pukOoN1Ar1YKJPQZcbgtuUwPfhI8D1RL0TcN/euFy9LUjaVq
         SA1ZhHfnCbw84QQIqthNEO9Ks+P0GXarhWd4AJbfGIHzNrP969IQrZewg2AM3NOc1qci
         qzHqiYlIooeJnHQ8Vj9Z/0SNCr+Uwd6Rxwon0FXTGHNSrtp1fmN2SILCJXJc0nRJxiI/
         QsBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZDLyBXlJ;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9tcruD+UxlfLlQR4273nkYi5U/qwNoKxPjAZPusNSJM=;
        b=C9vJuZlfou+f3NI5Iuza7W83ijoGhP4FNJjA3EGeIuUzX5btNM4UIFs0KBaa/bZhQJ
         n3LsMi5v1kIQ3Ip/79l8Nan0MAlyIujz1uC9NuzxmZFAxzGsb/HZOLOFkVryHXkmfrM7
         n3vQy0nFtu9UeaqULOyz+Yk+4Bz9MDXbtrxhv+k/9uu65pG9Cg//FpZhEZo1toB7pe2e
         svTiNZbH4T3uT1CvaMi4QuqWjFkx15DrXOQzTgn4oMf6WCmIFBp7VoonzShhtzQMn7Lk
         ryP3XxuuVrLwc2mE7+AkDY3GYBZcKMW0IPllhKvtEhl8Gl32T+euOd+Fl8ZhQEavKoui
         RiyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9tcruD+UxlfLlQR4273nkYi5U/qwNoKxPjAZPusNSJM=;
        b=PbklfDEZdEvdpQ63frYbvr/2lv8enoLG+fSBrv3027uTZfrMYUjOvOPyMvf6XcNuIl
         LufI56WEBT0oTMSMZTPdVbKDnnYC1EisrEwgCdydatrwAqn3FZ3SESGq7lJBol3tGZmd
         QTQm0QELcKRRPKtdLm8nYyBX29GkIyelELoBuOD1O7MLj9pXTN8hlcPaGt1fLGnZhbss
         8FRNaWNV/9B4TBTybC6koJtdWgG4XLJjPq5GE73heMmmUHAJiBXiYnNnURaqoh4vZ2yO
         Fp6KppFDWQyu+9dIxyp0sO99goJNdi0i/x97qxHQCBTohNhY5NOdxCH56amoWKMafGP9
         mUkg==
X-Gm-Message-State: AJIora/ieTAR5C8Jo2zyv50x7NCH7Mgkc3yo3T0N4hXsewyDloJblj71
	X9pAsVoG7fMBzJq8uZnXFgg=
X-Google-Smtp-Source: AGRyM1sCAwgOEimpFpvRXVOXZoO1liCqwY2cSF+jrtPwig9mGpMI0bE915nZqXZBTbxo6PpYC3ZJyQ==
X-Received: by 2002:a05:6000:1541:b0:21d:b298:96be with SMTP id 1-20020a056000154100b0021db29896bemr11158147wry.206.1657867786502;
        Thu, 14 Jul 2022 23:49:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3485:b0:3a2:e5bf:aeec with SMTP id
 a5-20020a05600c348500b003a2e5bfaeecls7120850wmq.0.canary-gmail; Thu, 14 Jul
 2022 23:49:45 -0700 (PDT)
X-Received: by 2002:a05:600c:4fc8:b0:3a1:99cf:7fe with SMTP id o8-20020a05600c4fc800b003a199cf07femr12311380wmq.142.1657867785199;
        Thu, 14 Jul 2022 23:49:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657867785; cv=none;
        d=google.com; s=arc-20160816;
        b=WOJ9MsRyY4uL9ELm39iTHIC5tZUyOkfbr2XlQrHg4P9cARhNz35tjHYF3pa75xX9t0
         gwJGh0VddZNJXs6Ci/sLeeLaZnNNPMviG3PA5e3i4Mmey7BtQgNG2DptOqy69WLw6OJz
         cvarJNqdFD8sDTUj7xZvUtIutOSY/zcCVspqmHpciMF0jyjGaZX5ulejb5z2S8TqtGl1
         VfWNBgJop4VneGsqo8mOf5L0ZYfBE2GmLwU7fRPUUnZQ4pKMYaKsz0BVZzY/AeChkxYn
         GP0jqBeF0rhlNjT+RJUgrSs7kiY3J7n7lev1MtDOuv4o9JUdseqieBNjh2l2nNi7l5Aq
         QY3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KnjfALuDTJDxp10CSGijGU7Lgcl//Q66oxYne90sBfk=;
        b=RV1TpefRBzm4cYjQsIwRrobEjUg5BEHw+vrBWZjmI4h70I2E+iDM2TzcfBAykYwolN
         +g2DgX/VBANpixmMlyautE2uLVT62vl9WoiD+54Sp5wMz8NaERe4r7B0rBeRw716t7xG
         DgIv7yRDys7uLNG0WYf3KVUA6G77a0ud1oelZ56TYh+0nXeDRQn5i2fx51shmP6YPZ6T
         yRhNNb9iaKO867NysbOt6gYymBuU59bHZCoi2XC9oy3NoNaYDud0AkcTZf4ddBqF+Wyn
         tuhjxIe3BsLu/UAWCoOFx/UQYgf8NLhQWfLqMUWlwaESKqCZvK9WAdhDCHz1/vXteq+T
         ItUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZDLyBXlJ;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id bv20-20020a0560001f1400b0021d835e888fsi94487wrb.0.2022.07.14.23.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jul 2022 23:49:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id bu1so5428804wrb.9
        for <kasan-dev@googlegroups.com>; Thu, 14 Jul 2022 23:49:45 -0700 (PDT)
X-Received: by 2002:adf:fd4a:0:b0:21d:8b59:dcb1 with SMTP id
 h10-20020adffd4a000000b0021d8b59dcb1mr11302010wrs.622.1657867784809; Thu, 14
 Jul 2022 23:49:44 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
 <YoS6rthXi9VRXpkg@elver.google.com> <CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ@mail.gmail.com>
 <CANpmjNOdSy6DuO6CYZ4UxhGxqhjzx4tn0sJMbRqo2xRFv9kX6Q@mail.gmail.com>
 <CAGS_qxr_+KgqXRG-f9XMWsZ+ASOxSHFy9_4OZKnvS5eZAaAT7g@mail.gmail.com>
 <CANpmjNP-YYB05skVuJkk9CRB=KVvS+5Yd+yTAzXC7MAkKAe4jw@mail.gmail.com>
 <CAGS_qxq5AAe0vB8N5Eq+WKKNBchEW++Cap2UDo=2hqGzjAekCg@mail.gmail.com> <CAGS_qxpNHrWxGBV6jcee7wPzkWTb1Mh0fpE7j4_0LrgeLv+4Ow@mail.gmail.com>
In-Reply-To: <CAGS_qxpNHrWxGBV6jcee7wPzkWTb1Mh0fpE7j4_0LrgeLv+4Ow@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jul 2022 14:49:33 +0800
Message-ID: <CABVgOSnK6pd2yPdxX6F+JNCdtk+xKVzbWyy9ffJeDM1eC5SsTQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: Daniel Latypov <dlatypov@google.com>
Cc: Marco Elver <elver@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="00000000000069beb805e3d26c80"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZDLyBXlJ;       spf=pass
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

--00000000000069beb805e3d26c80
Content-Type: text/plain; charset="UTF-8"

On Fri, Jul 15, 2022 at 7:48 AM Daniel Latypov <dlatypov@google.com> wrote:
>
> On Thu, Jul 14, 2022 at 4:45 PM Daniel Latypov <dlatypov@google.com> wrote:
> > Ack.
> > So concretely, so then a final result like this?
> >
> > $ cat kernel/kcsan/.kunitconfig
> > # Note that the KCSAN tests need to run on an SMP setup.
> > # Under kunit_tool, this can be done by using the x86_64-smp
> > # qemu-based architecture:
>
> Oops, this bit would need to be updated to something like:
>
> # Under kunit_tool, this can be done by using --qemu_args:
>
> > # ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
> > --arch=x86_64 --qemu_args='-smp 8'
> >
> > CONFIG_KUNIT=y
> >
> > CONFIG_DEBUG_KERNEL=y
> >
> > CONFIG_KCSAN=y
> > CONFIG_KCSAN_KUNIT_TEST=y
> >
> > # Need some level of concurrency to test a concurrency sanitizer.
> > CONFIG_SMP=y
> >
> > # This prevents the test from timing out on many setups. Feel free to remove
> > # (or alter) this, in conjunction with setting a different test timeout with,
> > # for example, the --timeout kunit_tool option.
> > CONFIG_KCSAN_REPORT_ONCE_IN_MS=100


Thanks everyone. I've sent out a v2 with just this patch here:
https://lore.kernel.org/linux-kselftest/20220715064052.2673958-1-davidgow@google.com/

I expect we'll take it in via the KUnit branch, as it's most useful
with the --qemu_args option.

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnK6pd2yPdxX6F%2BJNCdtk%2BxKVzbWyy9ffJeDM1eC5SsTQ%40mail.gmail.com.

--00000000000069beb805e3d26c80
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
z/tQRXr3iPeVmZCr7nttMEwGA1UdIARFMEMwQQYJKwYBBAGgMgEoMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZoGCCsG
AQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
c2F0bGFzcjNzbWltZWNhMjAyMDBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
LmNvbS9jYWNlcnQvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3J0MB8GA1UdIwQYMBaAFHzMCmjXouse
LHIb0c1dlW+N+/JjMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Y2EvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAx+EQjLATc/sze
VoZkH7OLz+/no1+y31x4BQ3wjW7lKfay9DAAVym896b7ECttSo95GEvS7pYMikzud57WypK7Bjpi
ep8YLarLRDrvyyvBuYtyDrIewkuASHtV1oy5E6QZZe2VOxMm6e2oJnFFjbflot4A08D3SwqDwV0i
OOYwT0BUtHYR/3903Dmdx5Alq+NDvUHDjozgo0f6oIkwDXT3yBV36utQ/jFisd36C8RD5mM+NFpu
3aqLXARRbKtxw29ErCwulof2dcAonG7cd5j+gmS84sLhKU+BhL1OQVXnJ5tj7xZ5Ri5I23brcwk0
lk/gWqfgs3ppT9Xk7zVit9q8MYICajCCAmYCAQEwaDBUMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAxMhR2xvYmFsU2lnbiBBdGxhcyBSMyBTTUlNRSBDQSAy
MDIwAhABh9LgIPnlfMFHR0Die8n7MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCD6
Gi0j2hMDLEzvaBl193pAKOfw6C/mR9ImhmUaK3wwqzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA3MTUwNjQ5NDVaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAZ8bjw0I4IHzJa1/jxZsX
09uyTuCgJuGkJuuLGlGoQ4cWZ+kFt+QGSuTZzG3z1LlriPJI6yU+tp3ICCpznawFsvj7g9YoalK8
TO2kqfy/YKKm+I1pahWLZt1s2pAA69Q01sZwZZaEwILAQMfdnfcv+AgwATFSTLLJBvQqZvNIEj0N
Wg7H/CjNGLjILymYq77k2N9KosE/7rf+6mV1NhdDNXYryzdIP01WvK6uhy2uKnvzCzoZqe57OyN6
qgxQ6+GZxg8DHkVs29KYmehc1XIQEDW0EDIepY613udBQ3Sh3trbMwo52cPLIhCIOI5YnYgrjdld
Y/znKCgzyvRU+MHrhg==
--00000000000069beb805e3d26c80--
