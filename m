Return-Path: <kasan-dev+bncBDW2JDUY5AORBMMMY2SAMGQEEWVQTZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id DD179736A12
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 12:57:54 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1a02fd9fd7esf3320851fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 03:57:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687258673; cv=pass;
        d=google.com; s=arc-20160816;
        b=0cCD+3CJOsTeTK4J23lLf/cdWugjWxAU/9s0MwIoVzgthWNK40TF3ndGJHa8USQhAC
         95IZFrzVaYeI6rkx9jDHSg4DVkyIx/nrhYhgz+bJwyQRMWCWT8VcJwxgPpWJiehJjdyf
         vUmovN39Z2gqt0CxieQ9BkZ8sXDdDiYN30t1LuVCXbySeiMaxiBLGc742P+gvqoYNDGr
         9GZa2yhZEohsfSzbBtlLBhbywfMeD+9aeqiVx+IHVkOpDgOrilUBw5WBcnVX1NBiXzgb
         sxTdXmygCA5B2jWN6Sy3AABWAMsnKQi8ie15X2vgnNg+yQ3Rtq0YMoneplTWgb8KiWeB
         EcNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ZDvR8AEr3Pb3UywxVpWe17FJQZodHGTuE9ZHMtAqQnY=;
        b=vHL2NgJGchzd7yXTedHmvmuqDi7R1ERS4ZTEwpE0vgjVJ4Gqv1i1UaQ4yuejye340u
         tuQQKVf3Pswp27La07NKlIswRUDsML0sGfpdwVTzBE1rLeQdSMoMi73aSFGLEMyOn7E0
         Qf7L7dNRKnjIUwf1lRUPKAdcWlyDoo39U22RJxGSMmYJVR9SN8h5dlvR/6Gi7ZcQB6GW
         xByRXaW6sbixLuvOzLeOBFLhgr8yFUCclVnUWa05Qy5BH7U0yFe2AWuO1UDMTwj3AkGr
         ee6u7sWCOgcLWcjXT1mCfSfYpe/+jT1mCQz3FzW9jgsIAw4Qohh6pQz8LM72ERuBwdMn
         MdVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=qm7g+dhP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687258673; x=1689850673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZDvR8AEr3Pb3UywxVpWe17FJQZodHGTuE9ZHMtAqQnY=;
        b=WIg6jPGwc+Mv/Q3/vi8T4zcmvycCCg9zAk2VhOAu7UYZHwxejg4fvpFiLA/wCBjtWD
         E8qYvjNtZkdX2UtbBnp1fCWrxchRhVHE/AAaaCMCs/xqJSzU+K+rs9yxfNbyW7YO40Vc
         PdA+bZYiJjjE/MxiwwOTvlEJtf84cdPMqRVIpOfZYiRhSn2oDxbIWcyxit7Dl56Rwbkk
         NTdf56WL/FBGeGgQGzXb2sdU6TdGRqvMhfO0CzhB22lJ1N6Pxrxeh+0ORnAjV01sXsr+
         SmO0gYHUOnwmrrhvJBWWqtjn0cAQZP4SITrxJnnWXBmbkiDMFl17mYhVp4Ty+m4sD6b1
         qmsw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1687258673; x=1689850673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZDvR8AEr3Pb3UywxVpWe17FJQZodHGTuE9ZHMtAqQnY=;
        b=TrJdep7vEMuCu1k710YlsJVNooU0TKAi6NExb8WqS7+veC1eQ9WuWujySsW+zDYAas
         jgnS9Fi4vtMZFK+JmHMRlEe66/IwdXD3hz3pbei0iuiZycnaAw+r0qa2ewTmjaqYeIRP
         97Vab05Evaf/wLC4QK7Lzk/boFV4sBjEd+j/SFQLcZu3zTvFX7uISVJrfkpirsHQDNEE
         TGXrC6+HRgYipgINAYTOTIXnRDiT7YaXCiXiSeX+V83UTbuPjKjdYcSeygbE7ZP70/MX
         qGQinz3ReJK4ZvNKy0FK3tElBL6Ga9BE5EniPZAOUf+zaZzc7p3TK35f9HsEXtIRvq+p
         W3Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687258673; x=1689850673;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZDvR8AEr3Pb3UywxVpWe17FJQZodHGTuE9ZHMtAqQnY=;
        b=FgI5W9ryUnbp1wA2T8w114cI/Ip/xeisIFErJE0dY9KDGUtw+MxYCetP8F8hRxbruS
         aAa5gkprpfd2qlktXGSq/Yhxh29mLQ7zr5W9VbpEb8Btie51Rn1Yl7Tmg1QUqAi15ouo
         tL0S/YFu4+aT/nHRI29ZkdkLfd6bNwkYn/iK7dsn11+/tJDgAfv0yhlxNQdms6puy7R8
         i3BfzUaw9Z5yx09PgqcyLJf9D1Qj4mYEko1CMJ0z6UpoutGWkgQW/uUZ1SnzZzWA2O7d
         82IsnEcnxBemv6hBpDlWJ0C0mHh9lSi5/Cn+/M/FefWhzQGtBaLedCJejPXz+ZA0pL6W
         EBaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy4TNGmjQfq5uthkofc5XxBi6GVjOS/r6kW4DfZt/wo9md10swF
	UHM+cQjeS86n4HvLDWRErSs=
X-Google-Smtp-Source: ACHHUZ5ymYavacm/XobTuRV61lNhiqvoOMk8Kz1l+36OA+mmDk7cBNkvOyibXya7jWII3RWz6ZRlyw==
X-Received: by 2002:a05:6870:c795:b0:19f:11eb:982f with SMTP id dy21-20020a056870c79500b0019f11eb982fmr10151473oab.27.1687258673376;
        Tue, 20 Jun 2023 03:57:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:560c:b0:19f:9b81:342f with SMTP id
 m12-20020a056870560c00b0019f9b81342fls1921709oao.0.-pod-prod-02-us; Tue, 20
 Jun 2023 03:57:52 -0700 (PDT)
X-Received: by 2002:a05:6870:5b08:b0:1a9:a956:33c4 with SMTP id ds8-20020a0568705b0800b001a9a95633c4mr10925981oab.3.1687258672825;
        Tue, 20 Jun 2023 03:57:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687258672; cv=none;
        d=google.com; s=arc-20160816;
        b=qySGLO7iwAlnGKspyo+FbRwfsvpQZmW6OTH4YmKz/iO6F5HQYxvSlQMOyjsS37NUlo
         ZWYapkBYz9+snkkoFfgei3vZAbtegu7P/+ZuXs92MANLaospu9JRcA8rv7IBZcNTEMqo
         WxzDYTKDtl02hi4wHUD2zwedxu2n2VsgNGkWtSHCiVOq2DqL/mbRSRQi2TQjUv5U7cJG
         rBmesfnOhmwIaVTaMdKzvEJU+JQprE5FZ3JHPHY/ZO1LQhEMmhpSPBdLTeusQ/R2J5/C
         KDB2x4+1+/LO40egZpiNC/0yXPUFElG/h/L2qLetxkLt1zvNVwJ9OdQSwBQrj7U0jA5/
         gU9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=w/mp0Ngy4nsVmS7qXoq+Hpkgz3O371XCxZT/IH4msvY=;
        b=ar0K65lTVKdIA571aTqWJZKQetoYMy9lIrMpsLCzVxielc8uTSib+n+2RO3hL79ajJ
         WQLOwC0cHu4GtxdnjBRLH08ATdH27H8FpYDklTopIhnRXrIhs/hyTTDP3RCxwoKUEjqK
         BEfOjMXzZYYiH/CpTgHtUyLi1/v1eud4KsrfdKNHTjeY0ULziQOlo/MV3KBdNWmBQw/q
         Koee5RYPGTmhzu0gOeQFf+MZvcJ9pwdvK4nxtAgSsMpVRs4YF3v2XOEd/KVcyMx+RMPp
         CDMvxDTYvinIkbfY0TdCX3qWGqS+MPZd9zf3MAfpiDiY6iWxonIYpVTjgwnomTQT7aG9
         M31g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=qm7g+dhP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id bx1-20020a4ae901000000b00558b743ef2asi171988oob.0.2023.06.20.03.57.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 03:57:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id af79cd13be357-763a2b6a739so148050185a.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 03:57:52 -0700 (PDT)
X-Received: by 2002:a05:620a:838a:b0:75d:5640:22e7 with SMTP id
 pb10-20020a05620a838a00b0075d564022e7mr11713898qkn.55.1687258672354; Tue, 20
 Jun 2023 03:57:52 -0700 (PDT)
MIME-Version: 1.0
References: <20230614095158.1133673-1-elver@google.com>
In-Reply-To: <20230614095158.1133673-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Jun 2023 12:57:39 +0200
Message-ID: <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Taras Madan <tarasmadan@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=qm7g+dhP;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Jun 14, 2023 at 11:52=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> @@ -597,7 +614,11 @@ void kasan_report_async(void)
>         pr_err("Asynchronous fault: no details available\n");
>         pr_err("\n");
>         dump_stack_lvl(KERN_ERR);
> -       end_report(&flags, NULL);
> +       /*
> +        * Conservatively set is_write=3Dtrue, because no details are ava=
ilable.
> +        * In this mode, kasan.fault=3Dpanic_on_write is like kasan.fault=
=3Dpanic.
> +        */
> +       end_report(&flags, NULL, true);

Hi Marco,

When asymm mode is enabled, kasan_report_async should only be called
for read accesses. I think we could check the mode and panic
accordingly.

Please also update the documentation to describe the flag behavior wrt
async/asymm modes.

On a related note, it looks like we have a typo in KASAN
documentation: it states that asymm mode detects reads synchronously,
and writes - asynchronously. Should be the reverse.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdy4TmMacvsPkoenCynUYsyKZ%2BkU1fx7cDpbh_6%3DcEPAQ%40mail.=
gmail.com.
