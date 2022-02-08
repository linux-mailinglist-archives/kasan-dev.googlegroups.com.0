Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBS7LQ2IAMGQEVLS7CAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id F35344ACCB5
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 01:14:03 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id f13-20020a2ea0cd000000b00243de4301e4sf5171138ljm.5
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 16:14:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644279243; cv=pass;
        d=google.com; s=arc-20160816;
        b=p58O7D0c8at2MeWDpzArOepBRLh2OUebHSGWd0J14BccNW8ZVagR8myTPsceMSI52y
         6AaxA68ZYGBegOlEgWNKRPhGva+WZrDG00cket9ALqG/TAOAKn9GQgBFeyNpCP9XErkz
         GkBMDfSpblDbkFaDcg1jKTBXgxXQHlH9Bmnv0pnb43IyaJQXIsaRmu4Mg1wBTevnWAkO
         ZjLHQi5dMmkdpAWL9cQdHKI7w8rY5z8OAwnSaocfmubyTrVRo/n1ciVrldXcQlXTAkkq
         PMazZjAiDVk88/e3tGguWnlJ8pp/chfMTrcUQocPH1KxTBnE8v+X/JbqkP7oyTx5W6+g
         xj/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PC+kHX5IccvzivlUtXHSFSIkq+3MPjJUVfgevhHvlz4=;
        b=Bd0yKUwmXUk8Mc8EbDQl4XdHqZpqIVCa+YRuw9PlFgVekbWOGziVw0WhjbYlDTrCHp
         ON4YVllr+P/R+yi0ez9Bv6hUE4aBwBkshUYMQPU3XlK9NAyrWcvSzofuEH182V6mrf1C
         cwwl1k0rQlNlOMKbWIqKhZdwb0iszzIuyuQF4+yQhwTIfbiT/WRgRjefPrrhZozfpzA7
         VbfNiU3sQFXiIAAFvDRWnewyKkZTe+CA0JdUodluHAH8Cb1mf8zHSZ8cdn2FtXsufwLX
         nOPE1W1geb9kJJg9pg3eJVpGYC756paHJoGK52EnoE32bdX9sD8JMcgOhl4QghtZrZWS
         OhJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U9EOQvYR;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PC+kHX5IccvzivlUtXHSFSIkq+3MPjJUVfgevhHvlz4=;
        b=LlexLHfXcvgJBGoWy3DJq+QmMVZkNDq0tm9UwmMDd2DetgWg5kE9I33JVRtkoTD1jk
         WQnwCG46iZhq9vJgiu6x1hPwIOyQzwzRfWqd6QEFxvCIBbdcC7WZrPOQknpL1ivml4d2
         1ly49C+70lfynZOgls7K8Y6AzDtTK/RhBCLXV8YGZMgEAkP2/SqtDOP+XSqcsWNJ6hpF
         y5VxpPTFBCv7y8LfafbiN3C8T7u58PEKn3aBiEsiC0iiBRjPHhrlo3lNhbJ2VnE+4jJj
         ib/VpmZ9shafo3rInt5GkkKDqL1y5JiRQ6z5iSDggVZLcCY2zM9rhFxOzjwhujjy7du6
         axHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PC+kHX5IccvzivlUtXHSFSIkq+3MPjJUVfgevhHvlz4=;
        b=vWN226484jvTl9zhplD2nM3fRQ0amFVHY1YpupOJ22AKeLbD+F5NE7ZWFxUH4kAi/l
         6j83w1lX3JXqVyyzR3Bp1Wc2feIZeJPMkT+uR9fmKcSTpk8caLpdkWRGitBZvGo2ZFEq
         xxFP1a2QjVs+QrjifSN3ck4LrnusTfd9DlLCpbrs1nRP3mZetLJJCBCXkXNFlq2kpGhA
         BP0HXLFs8baKkp9U5oQYYjeKjokuw4nyKASpkDjmWTnsRLf7VrTsvsM5SBNWGkYFpnTs
         syCzyqH/eid1MthgYqfNJVL+I59ve/LtGi0F9/qeBACvnEVwXKPUCJiLi0pn/AsNy9ht
         MVAw==
X-Gm-Message-State: AOAM530VeDKyY6uupakZQL2fVSQ5LhpYWe+29sz1ZmneKk1EEVTudMvN
	Cw4FBpXmvDppRlg8utCRSC8=
X-Google-Smtp-Source: ABdhPJxUXCA+tpJHzwMfdxh2zpS3ZI2AzqRQo4EzOVkgI+XD6Wp4slc6WVk/H8//aUf2t28WdAsBIA==
X-Received: by 2002:a2e:7f03:: with SMTP id a3mr1171056ljd.525.1644279243385;
        Mon, 07 Feb 2022 16:14:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1990:: with SMTP id bx16ls1657660ljb.3.gmail; Mon,
 07 Feb 2022 16:14:02 -0800 (PST)
X-Received: by 2002:a2e:9084:: with SMTP id l4mr1177463ljg.123.1644279242407;
        Mon, 07 Feb 2022 16:14:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644279242; cv=none;
        d=google.com; s=arc-20160816;
        b=rKK1F9mIqkWOsmVibo9hZ4qxeTeF9NZ8x/hIIQ7TQc7+2gse3uQF4BULHdO+fgvJ3m
         tpsquTT47gKAO8mQPycT0zz4N/n6Xfm8yYBqAc40kNsYuQ2sZ9onpWB3/i8YSMT3FVLq
         eLaLD9b0TsTd1g0o5np1nEwEnIzSxFvpGjQ15kSeWsIZ/AgIZR0MBP44+0s8Aw9njiFw
         fCRUwBdB/7biHX+Ao0IoFW08Mc+55NyiTWspB+22Y5RswDVDprL9g+pMtI8uqi5qI0mb
         cTlhw1QDJqjX+vJNgbxC7V1g5Wrz2NfWkChwo4iw8Y9zHPr7yMj7/NZ0LxU7fn7zMAXP
         Z/CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KrCYi30ISfoaw5otXa8VwSe20OUFBnQiOpbcWlrhJEs=;
        b=tK8KWF4iSaJh5EDDVk/mVUOtndGOdkwYOCI36zmkOZUFFnpMPVDlcsRv+xC6f0tyfc
         50D32pI8SbXGuQectx+cOkW4tr18NtzsG5Cg7j/TPTTC5ppnBPaxblo4bCGzc5nxJ3wH
         PEVDcPpc3q9i4a1yAco/PP1n9RorGe9sm0ANPTfyvhui1uqDdfWbL4IkrWPBpQHSwQjW
         8dk/wQMG0MBW+j/IpzyYHECATCd5vtZyhVyKDqLuyyCosUWYrnQB5MCygw2NL0f6tbvF
         nOy2p/MZfy7ReVUQzz7Fru+XBgwvctxzWJlhkYmPvw+Dq6i08ieLjW4g75gY2264RHMM
         YmGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U9EOQvYR;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id d4si66212lfs.13.2022.02.07.16.14.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 16:14:02 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id cn6so11079435edb.5
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 16:14:02 -0800 (PST)
X-Received: by 2002:aa7:d297:: with SMTP id w23mr1877801edq.313.1644279241995;
 Mon, 07 Feb 2022 16:14:01 -0800 (PST)
MIME-Version: 1.0
References: <20220207211144.1948690-1-ribalda@chromium.org> <20220207211144.1948690-3-ribalda@chromium.org>
In-Reply-To: <20220207211144.1948690-3-ribalda@chromium.org>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 16:13:50 -0800
Message-ID: <CAGS_qxptS8OaM=S0rHgbYi8_B4dXC4UssOCPaAZRg_oOEXneog@mail.gmail.com>
Subject: Re: [PATCH v3 3/6] thunderbolt: test: use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=U9EOQvYR;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::52c
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Mon, Feb 7, 2022 at 1:11 PM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace the NULL checks with the more specific and idiomatic NULL macros.
>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Acked-by: Daniel Latypov <dlatypov@google.com>

Saw one typo down below

> ---
>  drivers/thunderbolt/test.c | 130 ++++++++++++++++++-------------------
>  1 file changed, 65 insertions(+), 65 deletions(-)
>
> diff --git a/drivers/thunderbolt/test.c b/drivers/thunderbolt/test.c
> index 1f69bab236ee..b8c9dc7cc02f 100644
> --- a/drivers/thunderbolt/test.c
> +++ b/drivers/thunderbolt/test.c

<snip>

> @@ -2584,10 +2584,10 @@ static void compare_dirs(struct kunit *test, struct tb_property_dir *d1,
>         int n1, n2, i;
>
>         if (d1->uuid) {
> -               KUNIT_ASSERT_TRUE(test, d2->uuid != NULL);
> +               KUNIT_ASSERT_NOT_NULL(test, d2->uuid);
>                 KUNIT_ASSERT_TRUE(test, uuid_equal(d1->uuid, d2->uuid));
>         } else {
> -               KUNIT_ASSERT_TRUE(test, d2->uuid == NULL);
> +               KUNIT_ASSERT_NOT_NULL(test, d2->uuid);

Looks like this one should be
KUNIT_ASSERT_NULL(test, d2->uuid)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxptS8OaM%3DS0rHgbYi8_B4dXC4UssOCPaAZRg_oOEXneog%40mail.gmail.com.
