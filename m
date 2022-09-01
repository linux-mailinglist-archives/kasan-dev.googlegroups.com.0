Return-Path: <kasan-dev+bncBDE6RCFOWIARBOG7YKMAMGQE3H6CYRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D9D55A9828
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 15:12:25 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id b4-20020a05600c4e0400b003a5a96f1756sf1270017wmq.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 06:12:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662037945; cv=pass;
        d=google.com; s=arc-20160816;
        b=V9L1qbqQ4/kkZ3oCBpIwt0KXpvQ308uX/Waay8W8rlSxuiTb/3wdSDESGZW9i7LBMT
         Iqzuw68mdGtYzvruQCOlGP0YdfZmWP6IAcDIREx0ho0Yufpnjq8Zf9XHl4FgX9eeoJRm
         elLEbB1htLUbzo0aev57mZpcelRkUplb3370DM22OhK9SC906ZTjOzdbmUqjOaHdRCA+
         hI6KvlaaHuk9tKIgWSsKegDTAz0754EMQ2GxDXLMHt/MgqUH7myDtk9CEQwEV5ziRUvF
         HPwk/gTycdqYI6bHJ52x2Gz/cuPHNu/eLJAcyPtwIrfCS/c5zq1zbk4ByaVBVE00MGHR
         PPrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=5Bgm5j1gjvEx5y9ywVfESi5qGjGVv79eB0dyBxd7or0=;
        b=fnM8LQ7nLDPwolcFlcI1/ztCb4NQfKx9GkCG2V1vMkAR9M/XAMLExfGZAIc5BIMbmQ
         k6xzyf96Q0OGvYHhpCz4QS1jlrLNhywPgvvTiep6kcCUJAw4wa99aW5TVDTNoh/JfMGR
         XiBh7r2rls0LoiK3bGPHdkPGKE5QAJ7wvMFkLFl0FFqmnG3hCoJWvQ8rPTwd9uidO5kZ
         yi6wC1N0l7jIzWXEGdW/G4lc5rWCOULFgSiPf83nQZRPPcsb3dlF/sGg6PH8Qss/hvqQ
         n/wt4/R+LvtO8y1xGeDQ0YhJLdWb5QmHR4GJKtIKwtmSuVvWKk7LRMFRLbH2Hzl9hwl2
         hang==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XZmKOPIt;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=5Bgm5j1gjvEx5y9ywVfESi5qGjGVv79eB0dyBxd7or0=;
        b=dL/6QefkhqJwVoHnLgxZ4ia7100aNrRDxt+kbkZX/xuEUY6rbcIJuORQr2ZV+2sDZs
         +maYjkeE2tV1EnhTu0d3341DVhowsx1vSgl2JDTCS4UgMvgEajGVeH2SP1lzIDBhXp4J
         5avKuHaD5/JAV3CmXe3Ml8NgPPZDGXIZ4oXJRSZaTM1nfOCEXRJdrHVmH31rhvuLTFpn
         11hNUUaoU4WsZkxsHp5t5iLzF2i8r9gk5EqHQqvOFN1IhzUdCkJs8O8u4YVao+7YA/p9
         yiUTUFM+TEFerrVldhZIp1oLMqvUmkAc5/hAft0+olVqFMys4hC4AbR4sO2E5BkCvzaA
         JUqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=5Bgm5j1gjvEx5y9ywVfESi5qGjGVv79eB0dyBxd7or0=;
        b=h6ZW4KPyb2k6lswoMZdOksKrXIgyHNhPgLNCFQG+iucGO6wal9YY+9ARfldCQ5+X46
         60/SJ3qajo36EMj9AZ5stm9L9VtGQPfE5ptVc8CCNyl+SaCekuyzl2LclhgkvE9lD880
         NYCZraHATtybZV2WCjiW5KI53pf2UXcsvKKju44M/jWnIobCSpb+2Op0wEI32lAGR/kB
         SGKzRs3qSG/o40vd18nptxBj3jyHxAhIVl4V+anCqQuz+hWBFLn/A+5v/0Jh8fmRfblv
         9FnaDUsjEfL8Mc7wKVVFzL2k9PhMeX9CZ5upY3T85vBOWGLOe4jSuDq7UUNysRpbnBk1
         TZSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2PZnNgKBIW95JsDfvFwQKK8sBLz+siCyaUACSI+Kv8iVCDunsb
	IUVUY4Dw6IcQrRQtsM2z3w0=
X-Google-Smtp-Source: AA6agR6YM36oioK3XPnCygFsWKcCNmWPN+suzHfSzH11YUa5WMzvfcakbivFQntI9lHLEI1Ui54bGw==
X-Received: by 2002:a05:600c:350:b0:3a5:3473:1c23 with SMTP id u16-20020a05600c035000b003a534731c23mr5369811wmd.9.1662037944893;
        Thu, 01 Sep 2022 06:12:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:247:b0:221:24a2:5cf with SMTP id
 m7-20020a056000024700b0022124a205cfls3106555wrz.0.-pod-prod-gmail; Thu, 01
 Sep 2022 06:12:23 -0700 (PDT)
X-Received: by 2002:adf:fd4f:0:b0:226:d416:e852 with SMTP id h15-20020adffd4f000000b00226d416e852mr13537876wrs.138.1662037943897;
        Thu, 01 Sep 2022 06:12:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662037943; cv=none;
        d=google.com; s=arc-20160816;
        b=bQiBYQBqT3SQ8QerD74sW7cmzJTdsIGUVYlt0nhB3gWBAPqdx1JYPPf09gTbICbih7
         JOPNsRWTmZh5FGgcKgxpHTBGqO6BKuPZNyjQAPl86NSVbHE/VoywVSgX9miXwcNXOCg5
         jiTqzz2EVM+YGloOoxQ6N1/oAlaklPW/sZjgWRKnPOFeKqryeOPE851PQIjGPGIE/KST
         bKgvulmZwS1hV5VDuoGT5+ifA0HMoP6S6Ph9tMXqdJ83tn1G2bb+HGdzvABLfS7p7akA
         D6AxMU2UNjqNmCh9+GaWcPYxbqXnWe8E0OFGT0l1jCDgy8bLTRj+XrYcbL/BZ9sS5Sum
         nhIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G9R0QAAm6mXZOdYiAbbisy0joj2Ln2Tb7boXjxnlO/g=;
        b=A1FREMIK9qIa3VQDT+0h2wRqbgS3t6vx6z9nhCtvhcAPm+Vm1wlI4DqPUEQwGpzvFq
         AmXRt4qKPVg1wzVyeM+azbVPbB8miWYdISSOfKJmGmkFo+xs9vzhvF2qlTypFsF3uj1q
         pkSPW6eo/kMJy0WqREAFijFVD8fcek5vxg3sac7gt02zuittq/EFdAt5LJPN0+8OOeZ1
         Aj4lDyxpK9mqcCnZH7np48xIf4o20l+X7VrtZNMAJDaqc/QwMClc5Et3YHgRiVW46heG
         QMmxHfvhUbF48R9oHLwy4AtTpDMEg4m+0YNpJ7S1Sdvo6ZfMYsgtwL/Hnq+PDfjHwD0+
         HP0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=XZmKOPIt;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id cc18-20020a5d5c12000000b00226df38c2f0si476947wrb.4.2022.09.01.06.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 06:12:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id y3so34620105ejc.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 06:12:23 -0700 (PDT)
X-Received: by 2002:a17:907:2707:b0:741:7c18:4e76 with SMTP id
 w7-20020a170907270700b007417c184e76mr13260189ejk.690.1662037943636; Thu, 01
 Sep 2022 06:12:23 -0700 (PDT)
MIME-Version: 1.0
References: <20220827213009.44316-1-alexander.sverdlin@nokia.com>
 <CACRpkdYgZK1oaceme6-EEuV3F=m1L5B3Y8t6z7Yxrx842dgrFw@mail.gmail.com> <ccde957b-20b1-2fd6-5c90-ad9ee4b8924c@nokia.com>
In-Reply-To: <ccde957b-20b1-2fd6-5c90-ad9ee4b8924c@nokia.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Thu, 1 Sep 2022 15:12:12 +0200
Message-ID: <CACRpkdarYrhtrv2W8+MQm6QNFkrqE-EUVz4cm7kGvsbWgBdk+Q@mail.gmail.com>
Subject: Re: [PATCH] ARM: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
To: Alexander Sverdlin <alexander.sverdlin@nokia.com>
Cc: kasan-dev@googlegroups.com, Lecopzer Chen <lecopzer.chen@mediatek.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Russell King <linux@armlinux.org.uk>, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=XZmKOPIt;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Thu, Sep 1, 2022 at 10:42 AM Alexander Sverdlin
<alexander.sverdlin@nokia.com> wrote:

> >> -       create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
> >> +       if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) && IS_ENABLED(CONFIG_MODULES))
> >> +               create_mapping((void *)MODULES_VADDR, (void *)(MODULES_END));
> > So the way I understand it is that modules are first and foremost loaded into
> > the area MODULES_VADDR .. MODULES_END, and then after that is out,
> > they get loaded into VMALLOC. See arch/arm/kernel/module.c, module_alloc().
>
> yes, but both areas are managed by __vmalloc_node_range().

Owww!

> > If you do this, how are the addresses between MODULES_VADDR..MODULES_END
> > shadowed when using CONFIG_KASAN_VMALLOC?
>
> That's the thing, __vmalloc_node_range() doesn't differentiate between address
> ranges and tries first to recreate [already existing] shadow mapping, and then
> vfree() unconditionally frees the mapping and the page.
>
> vmalloc() KASAN handling is generic, module_alloc() implemented via vmalloc()
> is however ARM-specific. Even though we could teach vmalloc() about MODULES_VADDR
> and MODULES_END (and don't call kasan_ instrumentation on these), but, this is
> ARM-specifics that it's used for this range.

OK I get it. Maybe this warrants a comment in the code explaining the
above behaviour (also in commitlog) so nobody gets confused.

With that:
Reviewed-by: Linus Walleij <linus.walleij@linaro.org>

Yours.
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdarYrhtrv2W8%2BMQm6QNFkrqE-EUVz4cm7kGvsbWgBdk%2BQ%40mail.gmail.com.
