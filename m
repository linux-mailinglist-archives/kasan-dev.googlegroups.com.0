Return-Path: <kasan-dev+bncBDW2JDUY5AORB4UIXCHAMGQEVZEQZOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 1631D481F6E
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:11:48 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id j125-20020aca3c83000000b002bc93dd9241sf15921084oia.4
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:11:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891506; cv=pass;
        d=google.com; s=arc-20160816;
        b=UjHKq7+uyn6qD3SkI+tclJQtwfagXjN15mB3rZqPlfAjp8RUIIgFnp3rkUP8LByTTX
         Tx3OnFkQq4QckDvnxLkiDO7P4euiD4Lzg58nlnyEEy7+LBrC2IzW5V+8Zy9rYnfeeABs
         hzsdCRNodAmJxrVC+V2fKP/yfP849kXZFO9FpW8T8q499bR3hs/llLbtJDIzWz+Sx3Ls
         WJ0mX37LScvuyFVfVbLYZeFsnqiP67iVrZI1KnanhIR8u7lrOktHNOBTDzA+4fl/E+et
         b3F/0rguCXVWAhQVdLIxFmfFRfWwznoPV6dSZo2u5GmwiNctOONZTC1umxGTHcrPBW25
         qEJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=yuCPJo5+5XfbZWVlAWArM9awMV/5cdqIOWcndGTVcTw=;
        b=Rn6A4O5Pql5NfNkiSJ7mQlhC19MMRvjyFWYPppWU5dcDk8s4Edz/2+95d/mDMU/+9h
         VO8kiX1ZNRkax4GIXA+Z0TGhO93J+Mhb7r409ri1qNir/iBuwSaa7v160Adn2MrnVpCr
         8+Y402PUNXs5oxt7W+cAszUsxah0WmK0OVz99X58G7G7fXWpbKmqfUskLRXR7oSlew9+
         b4cMBivTwCKe5f0xfxKC1h7pjXj1B54Ymh7uj3VOe6lqskyfNrzQjXKKVD6w5LORxLBv
         1j2Y6XJwHr2tvt+6Oph7AJ1HHzK+q5K6TB4MBYsBs4aWoCANWvsMqNRJ5o804BzwBDjE
         yzFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fHvkh4Vb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yuCPJo5+5XfbZWVlAWArM9awMV/5cdqIOWcndGTVcTw=;
        b=qqUhT0l5KKwEynq+9zjRFHOrh/CGaFbbYQ/2aBxia5eoHC+D9GVbP+sAACWEcsepzP
         fGJuIa6gje/Lq1sBFw1ZH4F71hA84KRLepA9U/WB+LE8FcRX6jzQcBrraHAjbleoDWFJ
         LrzagqVXdgXnxAlmwIGTxXaRKUFR20jAGOm2Itx3lxHBnYhCbwDsmfuN+EarPLodqpHX
         MwBaRjLcFlkJ1XOpT/qNfOJEtos080tnXJeXdwRAmpkRWq9ohEF0lRudn3tutXB5VmwN
         eukJPopmFZJTjV4JUw3VBS+Jparp132rTFY2mnnZUyCrOYu0CXAv7zc5vYmWvKYs1hvB
         TS6Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yuCPJo5+5XfbZWVlAWArM9awMV/5cdqIOWcndGTVcTw=;
        b=abVFkSit062r3amkqFsxdaKTuXu6v4hK68/mLIWaPFy1fMbx9eM1JJaOP8F5hy7kq/
         am81xCuBd0899/gY2bBBEhuJw/s6MZpIr+YCoertNGplleLt/juhzHRm8AruBheSYVrt
         wuU0tYqrY3mEHOgbPI16m5fgMFJtwuNFRHqZY1arcg6eF7T3+JMytSibmhcgKILjm/iZ
         fr6WjlMjzeAUZ+SpgwkyLoNMU7LY1V9FXZyoI5mmwOaxI2i+8BYm3fALsvM8Nx0LkXl4
         WL1uyfhipRPe6AULRTlAjMVLFpHq8RZsun5x6lTYmVMkXfhGbBVD2MNHyabmLNDmkZVe
         /O0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yuCPJo5+5XfbZWVlAWArM9awMV/5cdqIOWcndGTVcTw=;
        b=tAj84AvR600y68HLwJG7wS7U12LZiF8XXgyf3Bqkcnsq0GPe0I2vq3i4vBtrIi6Rox
         ikvKKzlsy1g6kloSx3twm1Sx9OtGZ8uaHE2pR5JgVE/h8CYzNl1lq8oBWxf9Y/ZPTmVO
         gxBOfdxBeMigtPZI1uosQKIubE8ViMtMEjj6eQjRX9vIH6rPfPRjWihMzVKqncnxs4z0
         8+NYZUWhhHxu74emmkebfXoiMRX910iINRnSRJiR9fKnz0ZAMKzMlyFiiqGjVPqR87GS
         +oqzrS+UeTAyOzUeQ3yhpA9DwWw1FNttpCLFHmR8IScjwePlxqypEKz5NiijiMArw/Qm
         cT2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TicKe3BTb5Eam/yZLcYwe3gEoaO9LGi90arVG1+wCSgtUGv7e
	QnW9WzuEEbi3wz2Adk/Luiw=
X-Google-Smtp-Source: ABdhPJwXac79uKM5XIFmX+3vAdRMye+FbZHxlIsgHCVTj06D0ZeNvC0MGkv9sth0UhKeJlb+s4Xp+Q==
X-Received: by 2002:a9d:38f:: with SMTP id f15mr22668911otf.285.1640891506685;
        Thu, 30 Dec 2021 11:11:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:25cd:: with SMTP id d13ls5293094otu.11.gmail; Thu,
 30 Dec 2021 11:11:46 -0800 (PST)
X-Received: by 2002:a9d:7454:: with SMTP id p20mr22143618otk.307.1640891506387;
        Thu, 30 Dec 2021 11:11:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891506; cv=none;
        d=google.com; s=arc-20160816;
        b=U/IHyiMKPU8aLPGV11jbmjy2rp7z8AWv8hgHQlfDq1b377QzMo26esNuhpB2va7Olk
         PkVGVjxBbtocDBLpI/2Ni5pSegbhBFRGs8w7u8USbMA5RVs3FwjcSoQmCj8t7yBtxYnA
         1EtnQj0DQlYgxHBdlIHkW+l2kqKRjPqQ990MqnyVfAILjZuNhZSFgqaBEbKFV11/l8oP
         56XEXp+uOpbV38kqgo7kzo8W9AOrjvlf6XEzUd3EbLEbFN6UmCuGWicnVJRCeDTXgSm9
         8EZfEa8gNpvoUG/bC8LxdTh0Ud8SBCwZDeOOjpTcVF0rBmiZ70o9BsWPHFp/ThrqWWeR
         rfIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0fiv6RL03GYq28gBLTG+oAUxzJLFmuBgFQ32/iqru78=;
        b=I9a+kdP87Q5CJCOZ+7BC3yhD43Wu9GjD2aM/h6dcPOzGVINsT2JQItzmqT8JhBU04U
         S1VaP76Czj4RkOJE1dgoGzncGkzj048OpSQ0I5+MgfWvhrYL4UTGcLDAXtwCr59dOSH2
         Ltu7hPZEB5k0vW5dKlafWjj81zl5oAEMnA4EbGKCv9hbABGdgJtGQSTx/aB/oBzkq7Aw
         a5iotblfQcO4yjJWlSLqWCm7lleEeX1pOJq6JV0PDtwVK3sUsWrXEhUb/mlUaSW04+Ye
         cHqi5s/jFWdBW/wc8U6PIh3hlA8hzIy50mPUdJzqXQA3i3QTWW86dSUF0/jrxGBbVim3
         /DdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fHvkh4Vb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id b13si132146otk.5.2021.12.30.11.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Dec 2021 11:11:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id u8so30639653iol.5
        for <kasan-dev@googlegroups.com>; Thu, 30 Dec 2021 11:11:46 -0800 (PST)
X-Received: by 2002:a6b:7e03:: with SMTP id i3mr14544209iom.202.1640891506249;
 Thu, 30 Dec 2021 11:11:46 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <dea9eb126793544650ff433612016016070ceb52.1640036051.git.andreyknvl@google.com>
 <YcHEjERoiqJTKmsZ@elver.google.com>
In-Reply-To: <YcHEjERoiqJTKmsZ@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Dec 2021 20:11:35 +0100
Message-ID: <CA+fCnZdk1gksiMMJVMe-fb56_4ZFUaaOLa4EZx0RCSR-3xd4AQ@mail.gmail.com>
Subject: Re: [PATCH mm v4 29/39] kasan, page_alloc: allow skipping memory init
 for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=fHvkh4Vb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29
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

On Tue, Dec 21, 2021 at 1:12 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, Dec 20, 2021 at 11:02PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> [...]
> > +static inline bool should_skip_init(gfp_t flags)
> > +{
> > +     /* Don't skip if a software KASAN mode is enabled. */
> > +     if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> > +         IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > +             return false;
> > +
> > +     /* Don't skip, if hardware tag-based KASAN is not enabled. */
> > +     if (!kasan_hw_tags_enabled())
> > +             return false;
>
> Why is the IS_ENABLED(CONFIG_KASAN_{GENERIC,SW_TAGS}) check above
> required? Isn't kasan_hw_tags_enabled() always false if one of those is
> configured?

It is. I wanted to include those checks for completeness, but maybe
they just cause confusion instead. Will drop them in v5. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdk1gksiMMJVMe-fb56_4ZFUaaOLa4EZx0RCSR-3xd4AQ%40mail.gmail.com.
