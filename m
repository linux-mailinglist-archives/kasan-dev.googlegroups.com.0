Return-Path: <kasan-dev+bncBC6OLHHDVUOBBKPLSCSAMGQEYTK2CRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 152D972AA52
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Jun 2023 10:34:51 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-4f6275fdb9esf1921207e87.2
        for <lists+kasan-dev@lfdr.de>; Sat, 10 Jun 2023 01:34:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686386090; cv=pass;
        d=google.com; s=arc-20160816;
        b=mbPJX0KAi5vRaG/SZyomzxy/lPavdCifKtJiumWYfAz3vljO7HUIUPp5PhhXzWg006
         chO6OC5fgHqVwys4dJvKs/T4t4SP7Im579aTPtmG3tH5VWwXe66XZHqCgPCjv+XsUbGw
         CYOUcbWGefb0Dxl99HJXu+rcy+FbtdAiSUhfizMAOOLlAYFEffpaKUWsMqCj3btgKvO9
         fHDRnearTRKzZYH+xSad4fkar9QIBApMz5L83mHedzzYtQ+JwaiVHwPljbK+kR9A+gfP
         vipbBvF3bAPjr/PE4DuIi8nyxI/ww3byLDIGMsuJA6X9SRnlv/aXWxqmZVlaCsGr2uCA
         z7pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=02ZqaZf1scuheJhjz1iGWdRrmlUsCfiXg1cd1G34rEU=;
        b=08r5cu8EW4NpBdwkCVgjpzXkeO3JCibceNXKi/3STysi6wvT51ptUF0rA8n2KBBx5p
         89qYLtwWHSz5+GWadQzjmutNAQaa1hfUiOaM98jaGXmsuiItnhC0hQ7BpJrB+BxY1O5G
         QvdKXIBdXsPErA+IBi60zu5kaaVX7yobeQCS4KsZkgSklncmkyNI6L9Jxm+F/ky/IGrO
         OXEh+WYAn6lKSCTeg5NOPrayL0DLpNGW4DmqOet3dGPh+t8xUxWLp1b222zvFizY8XE6
         JhYJoM5oS0miM1nhFdbPaF4y+7thzCAyV1IDJWu6Pj957dLT27kMF6RX3g0QJ1sslLPo
         szbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=j73es8IY;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686386090; x=1688978090;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=02ZqaZf1scuheJhjz1iGWdRrmlUsCfiXg1cd1G34rEU=;
        b=Y4+jqWqvpDC/FXs7/jRvRon3xXJ5feyf2RnTaRw5UlErV9nm9QTRKMdtSPAv4CZVYj
         J1y9tQwBRMEuiBdW3U4IO0SIEIxQQoAnhv5/9ag6ihhjysnNjV0/3nzYzXZfOdG+vaK+
         0Bx8nAjA4No20p5vNKHJ3O7vbXAxgPTCyjyNrsZy6WMiT2VWkRUhAjUK3qaYeMW55R6Q
         9Kc8gq7mC5zLu4La6ql4T+KHmm8/sjVBAvG4J2GHZA7d+oSnnuoy+Q9CqdcqmOapKQJF
         YORxm1dMcB0dmUFdPlAgpCTJ5bgeYMUtBLVlZH6pBl/6+CSCb7Nd84mlcEHN/WQTnrFE
         cHPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686386090; x=1688978090;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=02ZqaZf1scuheJhjz1iGWdRrmlUsCfiXg1cd1G34rEU=;
        b=dGeeUrBp5lEUhvFyEi/7cWwxgfcmgwgKVvRzYlJ22DCqDzZuIjGDqIEZ1D78xC6Vdt
         J0jW3JrrUEH0OgwR0N6sWlUhWg5JmW+7np8J/gNq1suopq4DEy5Qsfaj9GQUyb4FZuri
         jbKpPBF/g7WwZbZQsXJAlh8dh18Cukony8xREiNLrNOCvfQPsEDUaITJOVQs2CCag8ON
         ZQ41856n1qFmca4hmc4/NV4xghqHO3ni0Mx0YGLLat4AAZ9EMJhcO5lNSyIA2cZ4LqbE
         E/xvVAgsP52Lf5dRmIj8I1YUhDLvGsrXDxWbDG1zesNKbcRQSExq8FjTngnr+6IApcSw
         xTnw==
X-Gm-Message-State: AC+VfDzJQSZ/BqYeU/AMueopGnWDqHfeuCgO7IZ+8FPSkuJXc/Cbzzq2
	av7Bw5qjHuJxvkjPX/AnhIk=
X-Google-Smtp-Source: ACHHUZ7uqzO1XEGFfz/QE/jQNgA60MoLC24Z/beypm2d1nCrW48uEj9pmDewmNgMZaj210ZzLaSSAA==
X-Received: by 2002:a05:6512:3283:b0:4f6:217a:5615 with SMTP id p3-20020a056512328300b004f6217a5615mr2251025lfe.38.1686386089702;
        Sat, 10 Jun 2023 01:34:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f95:0:b0:4f1:3be1:1d6 with SMTP id r21-20020ac25f95000000b004f13be101d6ls106299lfe.1.-pod-prod-08-eu;
 Sat, 10 Jun 2023 01:34:47 -0700 (PDT)
X-Received: by 2002:a19:6741:0:b0:4f3:a55a:bace with SMTP id e1-20020a196741000000b004f3a55abacemr1867386lfj.7.1686386087867;
        Sat, 10 Jun 2023 01:34:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686386087; cv=none;
        d=google.com; s=arc-20160816;
        b=rXhqM7TLvuvt54qIbHb311fYbxhBHBoRwHxl9qJt6Cih25eujzKJ+qQ6lks71OGc0l
         ljlHCNUikS7cH9TrkisdpgVpxOxG/nMX623dfVd9XbmXebfaCz9KU0OsgD265eF8HYIu
         1CaMvLcpMsJy+RDW9wBDyDJ5QV7rgEEb5jVWW+sPA5kn2+toDnY1nUcnSI8plcFF9g4C
         b4unUM1ZlPhGFNVfejp+nM0U1EXCYqxQlLmIIMrc5ZDbkJrNCL10N8UdfO83zfdmfVhw
         mN4kZh1SDCEqQKfOaU3DCkF4tnOhoc/DIXQa4rBOfqz17FDrYzxSgkkQnPTMZ41rApcv
         jSxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fm1AgC5l9dQvggOmRQ7OMpNYvdvP5+WtHMCy0FzZfqo=;
        b=BU4rmx4By/o2FMp17/DFodh4RuwUGMLeULVaqxUVqDMf3P2t7feMT4aZ+JKpctVhzF
         SmaNfD8Fdg2bSvS3rqSS/a3q9szlhsWxhE6+EOWoruFwQpLjrLUTTpX2zBuJj2KwkQ5l
         4I0T73VhJI1nfOdwaNc4tC7KWmV8FNCu7bkYtAGq7Irh9oKa+2M8rYM6DE48/ICdEBGU
         FX+SqEexR10BrVeROzkYRT68oEnlTnducygAEM9VcSpZSbKOwTemqSgXpR7G2pN3c+rn
         jXk48MscVdhJTYZwfum4Q5F7uU4B6F7j8Azd92hCj7JVLTN2RqRCslO3iKMJXGGpHPAW
         zRhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=j73es8IY;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id o13-20020a056512230d00b004f3a950560esi382239lfu.7.2023.06.10.01.34.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 10 Jun 2023 01:34:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-3f7359a3b78so32845e9.0
        for <kasan-dev@googlegroups.com>; Sat, 10 Jun 2023 01:34:47 -0700 (PDT)
X-Received: by 2002:a05:600c:82c9:b0:3f7:ba55:d03b with SMTP id
 eo9-20020a05600c82c900b003f7ba55d03bmr75932wmb.2.1686386087134; Sat, 10 Jun
 2023 01:34:47 -0700 (PDT)
MIME-Version: 1.0
References: <20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com>
In-Reply-To: <20230609-uml-kasan-v1-1-5fac8d409d4f@axis.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 10 Jun 2023 16:34:35 +0800
Message-ID: <CABVgOS=X1=NC9ad+WV4spFFh4MBHLodhcyQ=Ks=6-FpXrbRTdA@mail.gmail.com>
Subject: Re: [PATCH] x86: Fix build of UML with KASAN
To: Vincent Whitchurch <vincent.whitchurch@axis.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Frederic Weisbecker <frederic@kernel.org>, 
	"Rafael J. Wysocki" <rafael.j.wysocki@intel.com>, Peter Zijlstra <peterz@infradead.org>, 
	Richard Weinberger <richard@nod.at>, Anton Ivanov <anton.ivanov@cambridgegreys.com>, 
	Johannes Berg <johannes@sipsolutions.net>, linux-um@lists.infradead.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kernel@axis.com
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000b2ca3805fdc25b24"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=j73es8IY;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::333
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

--000000000000b2ca3805fdc25b24
Content-Type: text/plain; charset="UTF-8"

On Fri, 9 Jun 2023 at 19:19, Vincent Whitchurch
<vincent.whitchurch@axis.com> wrote:
>
> Building UML with KASAN fails since commit 69d4c0d32186 ("entry, kasan,
> x86: Disallow overriding mem*() functions") with the following errors:
>
>  $ tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=y
>  ...
>  ld: mm/kasan/shadow.o: in function `memset':
>  shadow.c:(.text+0x40): multiple definition of `memset';
>  arch/x86/lib/memset_64.o:(.noinstr.text+0x0): first defined here
>  ld: mm/kasan/shadow.o: in function `memmove':
>  shadow.c:(.text+0x90): multiple definition of `memmove';
>  arch/x86/lib/memmove_64.o:(.noinstr.text+0x0): first defined here
>  ld: mm/kasan/shadow.o: in function `memcpy':
>  shadow.c:(.text+0x110): multiple definition of `memcpy';
>  arch/x86/lib/memcpy_64.o:(.noinstr.text+0x0): first defined here
>
> If I'm reading that commit right, the !GENERIC_ENTRY case is still
> supposed to be allowed to override the mem*() functions, so use weak
> aliases in that case.
>
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> ---

Thanks: I stumbled into this the other day and ran out of time to debug it.

I've tested that it works here.

Tested-by: David Gow <davidgow@google.com>

Cheers,
-- David

>  arch/x86/lib/memcpy_64.S  | 4 ++++
>  arch/x86/lib/memmove_64.S | 4 ++++
>  arch/x86/lib/memset_64.S  | 4 ++++
>  3 files changed, 12 insertions(+)
>
> diff --git a/arch/x86/lib/memcpy_64.S b/arch/x86/lib/memcpy_64.S
> index 8f95fb267caa7..5dc265b36ef0b 100644
> --- a/arch/x86/lib/memcpy_64.S
> +++ b/arch/x86/lib/memcpy_64.S
> @@ -40,7 +40,11 @@ SYM_TYPED_FUNC_START(__memcpy)
>  SYM_FUNC_END(__memcpy)
>  EXPORT_SYMBOL(__memcpy)
>
> +#ifdef CONFIG_GENERIC_ENTRY
>  SYM_FUNC_ALIAS(memcpy, __memcpy)
> +#else
> +SYM_FUNC_ALIAS_WEAK(memcpy, __memcpy)
> +#endif
>  EXPORT_SYMBOL(memcpy)
>
>  SYM_FUNC_START_LOCAL(memcpy_orig)
> diff --git a/arch/x86/lib/memmove_64.S b/arch/x86/lib/memmove_64.S
> index 02661861e5dd9..3b1a02357fb29 100644
> --- a/arch/x86/lib/memmove_64.S
> +++ b/arch/x86/lib/memmove_64.S
> @@ -215,5 +215,9 @@ SYM_FUNC_START(__memmove)
>  SYM_FUNC_END(__memmove)
>  EXPORT_SYMBOL(__memmove)
>
> +#ifdef CONFIG_GENERIC_ENTRY
>  SYM_FUNC_ALIAS(memmove, __memmove)
> +#else
> +SYM_FUNC_ALIAS_WEAK(memmove, __memmove)
> +#endif
>  EXPORT_SYMBOL(memmove)
> diff --git a/arch/x86/lib/memset_64.S b/arch/x86/lib/memset_64.S
> index 7c59a704c4584..fe27538a355db 100644
> --- a/arch/x86/lib/memset_64.S
> +++ b/arch/x86/lib/memset_64.S
> @@ -40,7 +40,11 @@ SYM_FUNC_START(__memset)
>  SYM_FUNC_END(__memset)
>  EXPORT_SYMBOL(__memset)
>
> +#ifdef CONFIG_GENERIC_ENTRY
>  SYM_FUNC_ALIAS(memset, __memset)
> +#else
> +SYM_FUNC_ALIAS_WEAK(memset, __memset)
> +#endif
>  EXPORT_SYMBOL(memset)
>
>  SYM_FUNC_START_LOCAL(memset_orig)
>
> ---
> base-commit: 9561de3a55bed6bdd44a12820ba81ec416e705a7
> change-id: 20230609-uml-kasan-2392dd4c3858
>
> Best regards,
> --
> Vincent Whitchurch <vincent.whitchurch@axis.com>
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230609-uml-kasan-v1-1-5fac8d409d4f%40axis.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DX1%3DNC9ad%2BWV4spFFh4MBHLodhcyQ%3DKs%3D6-FpXrbRTdA%40mail.gmail.com.

--000000000000b2ca3805fdc25b24
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
9IGQSBx2i4m+hGXJpET+MEwGA1UdIARFMEMwQQYJKwYBBAGgMgEoMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZoGCCsG
AQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
c2F0bGFzcjNzbWltZWNhMjAyMDBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
LmNvbS9jYWNlcnQvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3J0MB8GA1UdIwQYMBaAFHzMCmjXouse
LHIb0c1dlW+N+/JjMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Y2EvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCRI3Z4cAidgFcv
Usqdz765x6KMZSfg/WtFrYg8ewsP2NpCxVM2+EhPyyEQ0k0DhtzdtGoI/Ug+jdFDyCKB9P2+EPLh
iMjMnFILp7Zs4r18ECHlvZuDZfH9m0BchXIxu5jLIuQyKUWrCRDZZEDNr510ZhhVfYSFPA8ms1nk
jyzYFOHYQyv5IfML/3IBFKlON5OZa+V8EZYULYcNkp03DdWglafj7SXZ1/XgAbVYrC381UvrsYN8
jndVvoa1GWwe+NVlIIK7Q3uAjV3qLEDQpaNPg1rr0oAn6YmvTccjVMqj2YNwN+RHhKNzgRGxY5ct
FaN+8fXZhRhpv3bVbAWuPZXoMYICajCCAmYCAQEwaDBUMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAxMhR2xvYmFsU2lnbiBBdGxhcyBSMyBTTUlNRSBDQSAy
MDIwAhABAz5xDls09r2CKyYRqnNbMA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCDC
NJZiAn+hqgx8mUgE5tg/WFkF12p49W1JGVkocyRU8zAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMzA2MTAwODM0NDdaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAaGi/kY9fzj3sRA/YOKO3
T+vr4wZhbAN4UWnpT5WKKFg2mv5CXN8VSjpQhkaat3JmiVnJQTyMAhpqUgS+fy19Pu7lXLja9bWd
J02Xxg59ebAX7o75EzTPgdGkpJJ4OXsrO/8WSZwlkR/Wobhb0NRjzeo2XwX/ryvgMT//mkVw1ff4
kdRF5Ix5kXT3Eq+6RjlDrAXVKj0kMW/nmDnLHtTUaFASh2oiZK6AmPdHT09PlQaESZjdV6vLuYLD
Cc9D5s/CBTPQt3bDO+/YnT3rNjtQvoHiJq0ffja7coR2CE1QBZ8Ot7ykdIxJ87bw+CpBfC8nN9Zk
BPY/Ed6ApQJIg4Sh8g==
--000000000000b2ca3805fdc25b24--
