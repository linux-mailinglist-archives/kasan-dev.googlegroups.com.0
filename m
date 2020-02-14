Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBSNKTHZAKGQEWXTVCDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 55EB615D35D
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 09:07:39 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id g10sf3082204ljg.8
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 00:07:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581667658; cv=pass;
        d=google.com; s=arc-20160816;
        b=BN4/qNh9c/sBMV7v0sB425Bk8JbnQDgtuhiwA3Gc1Avmbw/pypzgpkUstInId90s/Z
         MMIiwChe/sFD84RqbFWHtu6EX9mSgzDrixE+ceAzQYIjBUXnLqqSqQWILWY++lRadByh
         lQvM794eDZmTBxABgwCdKwmw8smTSGhs+2fhjPENtUa0cHFWNanZMenMvA2Bm0IAmthI
         UD4ZWtz8uCUkjKl1b4xzBNMwvSGDpqTJDd4sxDSbYZuEP0/xZoKHpU8OjCNpiUiQBNNl
         7lryanlJuv52905ZfW/+BU9Gh5ulpgG1TvBTjkLQ1qamtkaH8RawbRylpknc2QkPd4Tl
         e8wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=o64xy7Pcl2TQ1VVNqHwa7eQRgxj3n3sCWa1ELQo1+ik=;
        b=QOw/bfbNK1LCufCbq/FZmpC5fzLPxQO6frgngqNPtyi1qpfDwAHr6xPhETUESYeRtx
         LitkJcUlD6cGhjbw+M3l6oR1s061TO6wLNEY0HOgdk+UXuaiJKOpNEJw4Ht3TEYkrUSA
         eOOlnPSVk5kO1eBzq1Uysxrq+ynFrWMs4iytQx8r+6Ofl79OXkZAomAff7HW4Gm1DGvK
         ASByHgLnZl3toIkrVYr/NR8iqsAijj3Nk5Q1Mv7GHq3wMaxIuVNKqWwTO3VAEhlVdQSi
         G5Eb2GUcn1flNeiwweZXRHC/COISqha76UuNXy0jiDS6DU4KO+Z6aU7jOLmHTOevmmXA
         QDMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o64xy7Pcl2TQ1VVNqHwa7eQRgxj3n3sCWa1ELQo1+ik=;
        b=FlcYaWFkvyGkuYyR+YQxrsSNbRCJhac+tjNM7leCtSenh2E6XfwMpCmHPypoF7bmRG
         dj+lWRWLF36RPHqy6TrAUrBSdoHr/gVZggM4+fKlkEcUmbc0WdLENZGAKXxPwAFqTEME
         gTOvbamLS4uqwBAUv46pXSOC5PkbwZWO8t3PcJQo0PprwruGiB3AvbT2Dp1MXr0cqaSG
         bgSz9o4PAApfhXDNF1YJ6Jm6QfptDlulBiOBZS6X2VBgTNpdGJCJ7YreZ2iSQLuVy1VS
         EGzXzTNzrrb1o4408+hgb5RpyVVmlBGCS5saQ6rwLDsZviCf2J2zfzfjeWD7W0JT6WCN
         EdUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o64xy7Pcl2TQ1VVNqHwa7eQRgxj3n3sCWa1ELQo1+ik=;
        b=cx0yPzY2zQz2gnBvzhX3IOFLtG0EJJWV9XkwDGnxl3cboS6Zk8QKECZ++2VphcF4AW
         7OvFPWdAVmcXlUSqrmzSn2aQ2NK7LJHhMJumX91a1navD4nLNWnkE1j55CybgFMuNemb
         V3w2H6qGh/uHiiCO7cjy1aBnaeq1k8C7JgxUbJPAaVbmD3U+MH/oHUm/ZFfDiZkzkb+P
         /hZXn3pdv++XtX/hpHKSplWUi9c33Zy1k+3unzlLTRL+ZLix5TfzmnVj+tg8CsKTxB+v
         M5u3nmJHLSYAHNESSFOBfVhRIy62luJdqN9cmwMzRv6unHoC0FmzM0vdvDO3aEzszNS8
         2IcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWWV/YE+xBn6/DlWvd9zAKehNMjgB3aY6Eg5+wgoMZaksR+gC27
	tMuQ9eGbFmvCtJfrv2PPGHQ=
X-Google-Smtp-Source: APXvYqzXBCuax+vL5kFEJtbpEnxgH/AC5ZNtPWOTtIQvQbsKyR/0uDulb/va0r9PiAGlyMezYN0Yqg==
X-Received: by 2002:a05:651c:120d:: with SMTP id i13mr1268571lja.173.1581667657872;
        Fri, 14 Feb 2020 00:07:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3a07:: with SMTP id h7ls268045lja.3.gmail; Fri, 14 Feb
 2020 00:07:37 -0800 (PST)
X-Received: by 2002:a2e:804b:: with SMTP id p11mr1256809ljg.235.1581667657169;
        Fri, 14 Feb 2020 00:07:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581667657; cv=none;
        d=google.com; s=arc-20160816;
        b=myIus3r+D3qB5JvDZTUlGrEzhyJO0n0RlzQsQfcwmVfTmlxD6FQJ/XR3lPJgx+oSdf
         Wr+TMLQG9E2t9VsWhgTmgOSlj2tijoSEd1U/hej5A5dbbdAPop+KUd5c6MukQibiY9Er
         jnAv81iNTXlo58dIlhHQCtn066YlXM9F37J6A8bLIXvTGdMyVxh7o5VJCwyXMeCEjmDP
         1nyRoLyiIXL8N5yU8q8ig5GK5bakZ0Lv/LDNj5Ksm9tDVjOectR5Y7M6So2spCkr8ggM
         MEy2DLGp5ht/HAfK1FHDBAriOaM67e9LrxRtCFVYl8xV72AQyAuv1JP+GdFlaAWrIqab
         NtTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=EQbHxC3rD6W/pHh5MBxz99eSi7EjbdxkjuMX8cwMLF0=;
        b=MYJvTbHqyNLYbXmQolArxMEO+faffe5gt/ZaletRVC9D0IR2YQikE8o0ClVmMsGg6r
         6VS01GpoF0tDzt1Qb7kGlZMyRqWceTRlRmKpzH+jN0UwCEdivIiHoVwjzY4iv9ADocBm
         YPWFn03RYSGPGtSr+pxtm38LffV1RpeBPYSESgEiaIDupjibh2ZQ/j07OfFQQPkatqGw
         0ZDAhqGEGZ4tOLqyI+4GlKdeA7gB0At1bRp0fP59Ty9+qjV/j7RE+c/ACycH44nsFFwu
         KnHDXMRR3hB5964uZhH7cPRUnY/Dm+8pNPxCI6H7c7XJxJBWfKn6ZbV30OYaMymjuPsv
         knRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id e3si278700ljg.2.2020.02.14.00.07.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Feb 2020 00:07:36 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1j2W0W-00B5oY-In; Fri, 14 Feb 2020 09:07:28 +0100
Message-ID: <d8151ac6b1e590d6c49d8c890604a08685cd2303.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
  Dmitry Vyukov <dvyukov@google.com>, David Gow <davidgow@google.com>,
 Brendan Higgins <brendanhiggins@google.com>,  kasan-dev
 <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
 linux-um@lists.infradead.org
Date: Fri, 14 Feb 2020 09:07:27 +0100
In-Reply-To: <CAKFsvULfrFC_t4CJN5evwu3EnbzbVF1UGs30uHc1Jad-Sd=s9Q@mail.gmail.com> (sfid-20200214_015457_457274_397896E3)
References: <20200210225806.249297-1-trishalfonso@google.com>
	 <13b0ea0caff576e7944e4f9b91560bf46ac9caf0.camel@sipsolutions.net>
	 <CAKFsvUKaixKXbUqvVvjzjkty26GS+Ckshg2t7-+erqiN2LVS-g@mail.gmail.com>
	 <e8a45358b273f0d62c42f83d99c1b50a1608929d.camel@sipsolutions.net>
	 <CAKFsvULfrFC_t4CJN5evwu3EnbzbVF1UGs30uHc1Jad-Sd=s9Q@mail.gmail.com>
	 (sfid-20200214_015457_457274_397896E3)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

On Thu, 2020-02-13 at 16:54 -0800, Patricia Alfonso wrote:

> Okay, so I'll rebase onto (1) and just add the lines I need from the
> [DEMO]. Are you sure you don't want to be named as a co-developed-by
> at least?

Yeah ... it's like 3 lines of code? Don't worry about it :)

> Yeah, failing loudly does seem to be the best option here.

I just ran into that with userspace ASAN yesterday for some reason, so
yeah.

Perhaps good to tell people what to do - I couldn't actually solve the
issue I had in userspace yesterday. Here, could tell people to check the
address where it's mapped, or so?

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d8151ac6b1e590d6c49d8c890604a08685cd2303.camel%40sipsolutions.net.
