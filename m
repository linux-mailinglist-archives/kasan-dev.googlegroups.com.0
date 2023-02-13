Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQODVCPQMGQEUMSKCAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 074266944B9
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 12:40:52 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id z14-20020a056a00240e00b0059395f5a701sf6200712pfh.13
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 03:40:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676288450; cv=pass;
        d=google.com; s=arc-20160816;
        b=HyiB6Vb9pQiGqhT+GXGvD0H5j+gNUEBN/W6aovtOjl4ZdnzK6PcYiQDYzpi4Te8Bq/
         ptVQSsMUXvcdFelBZDpx8pVtTBPxDsgRaKqmeqecOmahBeKP7EM8rLFPh5nghjInv9mQ
         Quf5yQSYVGpAb+KDjPymspt4QgJwPkSRENqrwnXyldU6uYQcKReJlH38cm49R1nDC9Yz
         KcuZcGvb5DWmZUm4ytjqd14Ayj1KCO2AW0TPCFHdcHDUnyBOrqBAKA0CUzVrhFqgkrD5
         6Zy7SAhVr7dczSsPAFQnqMcb+SUlgcF/yhpHdtaBg9HpMW1/vI0mE1sgJ8kZ1W2GX5eH
         D3oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jkf/aiMoUnHI2kz08q14sfwYigMHUumNF9JRtM0GCoc=;
        b=SrRDmbvQbaxzfJQFnYVoEX6Xg8bOvcE8X+HZNQtX+Yzir5SIDpcDRn9Nf72Evz4yZj
         XVeGdvTgB/bAdZwzpGg2awaQimT+gScID/7d4q9csStGt2cEyxFUqrOrS2m15DAe0j0f
         e8VdsQE6288SPxYRFiDSaxakmCAvj7WueZHbUhW4PL5fqve5eNaYCdeKOyqgueZJeh5I
         iGuLrlJfvIzK22vv+C3LKDEKfGJWrLMM0PHuo/ukgRhvCAjBxeSZltxtQc+al5beXPI3
         nHsR6WkiH8ILnd8Utrk40CdC0WSj/dm4UL6YdIeNHa08kO2q/bgDM4DOWvjTkPDbykCv
         LRfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gjzq7/aq";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676288450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jkf/aiMoUnHI2kz08q14sfwYigMHUumNF9JRtM0GCoc=;
        b=EA085ot7RJFDDQbCxaPEzuALj7WWXmPu5E5vp0NaEniD84u7+mmHkyOs6dJFSAl8n1
         SXrod799/ngg5VTXDdXxSKQF+/N50kAbQSR0NjqNnHBXT2L8E2hDZntn6aMLv0eCpoW9
         M/f8Ah1KW6sRptfN2rM9JD9vqhbYa1Xrcoi3DNF+0MLpdLz3jvWwQ99GkQDH6zeXZTbh
         sihLWdKQuFTyVyNHdgBsX4X5rYg6PtKuvlVlG6THQSCf2PZDVwU9db/TPHw9gKDAi3ce
         Rxmunp2PuiaH1kevFTwbs61lZaA1w28C+OeHWQfEKSD6vdzG8bxkp0KJ0SXQZiaouJpf
         gVQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676288450;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=jkf/aiMoUnHI2kz08q14sfwYigMHUumNF9JRtM0GCoc=;
        b=Enex3DExV2p+AkDXdlQT/B7qeG6qLutZMJEimiTzc6WJKnAh186Gr8iSCKdIB+QdvH
         4fgnySeTppKteHerX6HeByQAn6ngSlQnlnoyJRtFAg84J+FcsGa5Egx7hMYI7p9p88aY
         vNHooZjLeDdnQBY9suB9i6U7P/uJVB8Y5DjI9LxCGVFcMJ61H9450PtQ/6L82N50r5o+
         rMoLQ+uLk9RGtY54hmtMGQojiO52duoV4WAlR5SbXXz4ybxmyvoA05DJFNa2AS17ruta
         lFFrXF2P66fCIrlf/QtID6sCCiYhPT2BZQ5/K/B6k+CjU/rBklkeD2kAtcFUubcd+qcJ
         AtdQ==
X-Gm-Message-State: AO0yUKWUXt9Wo/DXz66wQTYEtgaAsEGk/vQo84CgsZC1CtMmnI7wT9rS
	p+fZWl1hKg4JlrvotobPNwo=
X-Google-Smtp-Source: AK7set+AC6jy/Ef5TiwOD7zH3x/OoV33mMqDG4mRUHuN8Lk3XzVri2vcm+zZIosdn2Sp6mr1XLY7vw==
X-Received: by 2002:a17:902:7884:b0:19a:721b:bce1 with SMTP id q4-20020a170902788400b0019a721bbce1mr2460912pll.23.1676288450071;
        Mon, 13 Feb 2023 03:40:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f293:b0:199:50f5:6729 with SMTP id
 k19-20020a170902f29300b0019950f56729ls3358118plc.11.-pod-prod-gmail; Mon, 13
 Feb 2023 03:40:49 -0800 (PST)
X-Received: by 2002:a17:902:d4c2:b0:198:e63d:9a4f with SMTP id o2-20020a170902d4c200b00198e63d9a4fmr26954496plg.47.1676288449395;
        Mon, 13 Feb 2023 03:40:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676288449; cv=none;
        d=google.com; s=arc-20160816;
        b=wqTVPyuKOKI0/PrgxGn+kcAChmgAbJJCNAxFWnr4PSdxohsnGpL/9ceoFBQYwByGOp
         IqrGCgYaQkMxV6w2IdoSuGpWdTZSRvnezeYWT/gbihwRNfp6DlTvI+9RPMUkaIfpigzX
         wLzKKaOlHvxp96Db5NFCxfh6pVoMi68ODBjlEK5bqGULhmjau0ICnc9bneY4c/J7xRG0
         fzZkbTD7kT82JN5793CPRX/E34/nfOwYD8Brm5s24ueD5GIhJk8y69OVtXQi/j+Dj3sL
         KCzwHv4xbop7iF9P7TCurzS5l6l12PdvkSqX/NN3N/X2n9K9HZwB9Ig2OAZeEnwIGCRf
         xq/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qNo1hAJNIesNvAPFE4VcY9SxxfJ87Kojc4RqWUh0cGc=;
        b=YcqujAappYuSTojflF98MRuMazArkCwecbpNoOl5WIte2f3x0NiDEBcM+JxnAArF2M
         nsrdryLH1GJydQLTaFeIt+hgaYwp2klynFRXyBWvs3SLjd7YtKF7eepPPPODYb52oV5h
         EKR6Sj40wy3lnO14yUMq6CLs0zrg5+fhnN6Zj21xU2XRJIKpGXMASYCszvNgVeQg8rKk
         rjfBEmWZX89unZPLryjJcNdyvoitH6SYKTcRkBC2+p1E7YHCJyv1+voVuvC9G9igl0nS
         ALpz0qo+2XoRbZpY0jl4sFCrZ1MlVwrdo9WE31TEhbRB6ZnNo3TCE9cJ3EdkloRY3xSL
         G1DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gjzq7/aq";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id k20-20020a170902761400b0019a6ca00d0esi204806pll.5.2023.02.13.03.40.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 03:40:49 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id b9so4872471ila.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 03:40:49 -0800 (PST)
X-Received: by 2002:a92:8e43:0:b0:30f:5797:2c71 with SMTP id
 k3-20020a928e43000000b0030f57972c71mr13112784ilh.51.1676288448825; Mon, 13
 Feb 2023 03:40:48 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <317123b5c05e2f82854fc55d8b285e0869d3cb77.1676063693.git.andreyknvl@google.com>
In-Reply-To: <317123b5c05e2f82854fc55d8b285e0869d3cb77.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 12:40:10 +0100
Message-ID: <CAG_fn=W+DHE557+u66qAUbo9tjL6qgcktEJPfTCzFRAE7Ckd5A@mail.gmail.com>
Subject: Re: [PATCH v2 15/18] lib/stacktrace, kasan, kmsan: rework extra_bits interface
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="gjzq7/aq";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::133 as
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

On Fri, Feb 10, 2023 at 10:18 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> The current implementation of the extra_bits interface is confusing:
> passing extra_bits to __stack_depot_save makes it seem that the extra
> bits are somehow stored in stack depot. In reality, they are only
> embedded into a stack depot handle and are not used within stack depot.
>
> Drop the extra_bits argument from __stack_depot_save and instead provide
> a new stack_depot_set_extra_bits function (similar to the exsiting
> stack_depot_get_extra_bits) that saves extra bits into a stack depot
> handle.
>
> Update the callers of __stack_depot_save to use the new interace.
>
> This change also fixes a minor issue in the old code: __stack_depot_save
> does not return NULL if saving stack trace fails and extra_bits is used.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW%2BDHE557%2Bu66qAUbo9tjL6qgcktEJPfTCzFRAE7Ckd5A%40mail.gmail.com.
