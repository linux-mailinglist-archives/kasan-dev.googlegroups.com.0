Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEE4TCEQMGQE7S6DJVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 749D53F71BB
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:32:01 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id c2-20020a63d5020000b029023ae853b72csf13848297pgg.18
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:32:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629883920; cv=pass;
        d=google.com; s=arc-20160816;
        b=RP6wpUBZdna+cb3nPzaaegAJN2p+IE0bicTftLV0UB5H+V8iDMOmKHr1BLPqH73ukJ
         q069lPnA75B9Ua/JaWEi2vOJn/P8mCHGrhvuUGPavm5gIJ/wLoeEGuHcHs7jqFIjLgEC
         i1f5H+s5M50JlHXqC+1lp1Ccj897k8oDfQMk8qKrtEJAYcJgG2NZUxvBBxZQNr+qMTwC
         rBjQZb35sCRF9faWAVd6Q1uwpix7IIwBuzujd0c92hpXmvFQZdbRbFj1V4XZWiw+RWfN
         iWTJGo90lp1bpNxhDnHz8WmJka3hM8J3gcDfs4JVK/l/UcOZ0vfe/DECkwvO0BgRwLbp
         vfpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vHp0PIJoV64RgHQbKin87I9NVYx/dDJNCKwaH9M7/0I=;
        b=cMSTg1UBhvGp4pxclWpYe9NM88gyJq47pLkjNwRbfhvDXLv4DUF9vXdMcfsIOcgl3I
         BL1hcDWg5cJALR6OjVU4ZeAFIZCFQBEJ5g8NLDvlPjTirNQt3NFp5w+s3wqreL1l1srJ
         IPlt75O03L5v8055H9DYvoy3x7DxO9EGeYaWyyhFvlH85tIH1Bb6DPjKQbiadKQnyn7P
         drVgYNA1u/CAL4neOBUnCH5Cv8Q7oSgikMn0g/IlP/gwunQHA2UaPFZQZb9FtLlFyWNK
         8xdeD51O97n5/ViINkXODAKE0ohEbmonyWNU+FaRw49xEJobUyaa7rmIVsWkV5neJ/Ze
         dgEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o1MLlo1f;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vHp0PIJoV64RgHQbKin87I9NVYx/dDJNCKwaH9M7/0I=;
        b=LEICwZjHTdroHPcrfkLckAdXUkVp6ULJuJKEFgq6GUMj9aBpTW2FVMmtlDlVJm0Uf3
         nX31KyBxzEX9GuSguxD+nr89pNH+u37/17vO9z8W84CnxIwEsVVq+Ij2zy4ZYkVhjgNC
         F4r1PfX1ItsYu/IJZovs8FTY780F05VimB8YNSFHW0Ox1eL2cjj/9UmBzxlA8B6jfZGy
         L9IUZrKlkWvWPSCgKfVCWFcgSmJVnkHHn8yDBoEoexbKxLAnVcjcnS6hvAKyFEY4RVWz
         pKbPKbI3wUJ4W68CSFHlETdlhbmN1eobNfyG6YruHlW6pcOZ5dueVrvJidfZ3wpMz9Fo
         cwUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vHp0PIJoV64RgHQbKin87I9NVYx/dDJNCKwaH9M7/0I=;
        b=J50Xuq8NNhMY9W96AY8Kq9v+AF2bLDgouSoDnG09IRLtCCU9XqJEklI3EEmR4FEvd2
         l11MNvGoIiy4QyOvxfgKdq6Wp17mcgQK5C6YTp9+Fm9nRhzN898BRPyr/xAGLzrXAPt9
         5BBXW+UOBj5gfy2T6hOjoBhHRLFtGo+QS2TD0vR7xxuLe6A5Su4/Y/WEahLtCoItDrt8
         d/CgadcoIUT/NYP2vDd6EMWbReXofeXKtahpw5heXhkah7QXyW+XM5uO0qWTWHhXdrbe
         OPnIcGgUcOJTVFQtpd1naZPsWlS4AY7AOrV6ZCkp8B6b1hoiUJDgMg3tdL779DaiOEEh
         klpg==
X-Gm-Message-State: AOAM5328LldPWmWQDF8dNA65CBycXYI4lk2w3L8jAPOj5XJvzE5HvZv5
	ee3eW3EGkRbOkThz/+Gr19w=
X-Google-Smtp-Source: ABdhPJxWhaiYAiA/Go3S4sq1UL6qlwpcC9IWro1/lBZrYKI4uJIP4zNqbrFQs70TGIBlmIu4hfM6Hg==
X-Received: by 2002:a62:798d:0:b0:3ef:72a4:e899 with SMTP id u135-20020a62798d000000b003ef72a4e899mr2764055pfc.13.1629883920116;
        Wed, 25 Aug 2021 02:32:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4d2:: with SMTP id 201ls739247pge.9.gmail; Wed, 25 Aug
 2021 02:31:59 -0700 (PDT)
X-Received: by 2002:a62:e70b:0:b0:3ed:7c2d:8052 with SMTP id s11-20020a62e70b000000b003ed7c2d8052mr8417139pfh.51.1629883919595;
        Wed, 25 Aug 2021 02:31:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629883919; cv=none;
        d=google.com; s=arc-20160816;
        b=J5NaRFVwtvduk+jjqH0Uw4VCf/AXlqoy5r6ZIZBomIzZ8guNp7tw+L1mCiqW7/gfTh
         EBQys0Vo6Ro+N8bmyokULjNiNi/dbi+VBH/3482JkN+Y9aHAP0OXQ6aTaxqv1W2Glblv
         WieVXmqHDXJ6siIiYxPR5o1XcAAWadxfAs4+aYHt7kuPgzDELBzKtFDnQMjn7QvAENTo
         eG0cyRsoXu8d2LqNOlaDYdjEa33hTChQhX7XgUr933h/jmsgD/YYnexKIidCkyOSnYI7
         iOZvvFcfjOotiJgSrm5CDBl89OplFpRboufQw6HEQ99ctJYBK8qbWxrlQzr7WgAu6Z1t
         O8VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nIK28OMLuwRHSdvdEpMN380N/Y1YA/9aI7TDeyqQyqQ=;
        b=iuLbI8qrll26jshzpuZTHjUkglIjupuCGBc0uK+wyxlzx9k6Ffpdu3F/7Xm4y1gnbp
         KgM+UW5Vai3jJCbpoi0f1p8oGSMVW8twde5ij03LRM0GkugeCdwYld9IsrgOz79VBjI+
         J/ziYHcSVbcX1KAFdVEjkjIVumeXMfEh74x12pKjZZldZE10RSlzaWwmrvOrT/F8e12i
         x57phrYP+zX3hgcGIloccDhA9Nml81R/IcGV/AeBTeRoRCHkcGjaXwNAOPVF5HDEHqe4
         yMuvc6sxRbAQC3Pp2dotYkkJ9bqIUjCq25187Bnf+u5TpUDjsoIlwnBgzblHwE4czwF6
         jlzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o1MLlo1f;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id j12si1354922pgk.2.2021.08.25.02.31.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:31:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id b64so12483362qkg.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Aug 2021 02:31:59 -0700 (PDT)
X-Received: by 2002:a05:620a:d54:: with SMTP id o20mr30711262qkl.326.1629883919020;
 Wed, 25 Aug 2021 02:31:59 -0700 (PDT)
MIME-Version: 1.0
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com> <20210825092116.149975-5-wangkefeng.wang@huawei.com>
In-Reply-To: <20210825092116.149975-5-wangkefeng.wang@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Aug 2021 11:31:22 +0200
Message-ID: <CAG_fn=X9oaw0zJrcmShNcvd3UsNSFKsH3kSdD5Yx=4Sk_WtNrQ@mail.gmail.com>
Subject: Re: [PATCH 4/4] mm: kfence: Only load kfence_test when kfence is enabled
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Russell King <linux@armlinux.org.uk>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=o1MLlo1f;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Aug 25, 2021 at 11:17 AM Kefeng Wang <wangkefeng.wang@huawei.com> w=
rote:
>
> Provide kfence_is_enabled() helper, only load kfence_test module
> when kfence is enabled.

What's wrong with the current behavior?
I think we need at least some way to tell the developer that KFENCE
does not work, and a failing test seems to be the perfect one.

> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>  include/linux/kfence.h  | 2 ++
>  mm/kfence/core.c        | 8 ++++++++
>  mm/kfence/kfence_test.c | 2 ++
>  3 files changed, 12 insertions(+)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 3fe6dd8a18c1..f08f24e8a726 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -22,6 +22,8 @@
>  #define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZ=
E)
>  extern char *__kfence_pool;
>
> +bool kfence_is_enabled(void);
> +
>  #ifdef CONFIG_KFENCE_STATIC_KEYS
>  #include <linux/static_key.h>
>  DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 7a97db8bc8e7..f1aaa7ebdcad 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -51,6 +51,14 @@ static unsigned long kfence_sample_interval __read_mos=
tly =3D CONFIG_KFENCE_SAMPLE
>  #endif
>  #define MODULE_PARAM_PREFIX "kfence."
>
> +bool kfence_is_enabled(void)
> +{
> +       if (!kfence_sample_interval || !READ_ONCE(kfence_enabled))
> +               return false;
> +       return true;
> +}
> +EXPORT_SYMBOL_GPL(kfence_is_enabled);
> +
>  static int param_set_sample_interval(const char *val, const struct kerne=
l_param *kp)
>  {
>         unsigned long num;
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index eb6307c199ea..4087f9f1497e 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -847,6 +847,8 @@ static void unregister_tracepoints(struct tracepoint =
*tp, void *ignore)
>   */
>  static int __init kfence_test_init(void)
>  {
> +       if (!kfence_is_enabled())
> +               return 0;
>         /*
>          * Because we want to be able to build the test as a module, we n=
eed to
>          * iterate through all known tracepoints, since the static regist=
ration
> --
> 2.26.2
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20210825092116.149975-5-wangkefeng.wang%40huawei.com.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX9oaw0zJrcmShNcvd3UsNSFKsH3kSdD5Yx%3D4Sk_WtNrQ%40mail.gm=
ail.com.
