Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBY6VQDYQKGQEPQDKPEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 28B2713D6A7
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 10:20:36 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id l2sf3724184lfk.23
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 01:20:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579166435; cv=pass;
        d=google.com; s=arc-20160816;
        b=o/oax+KlK0CPepfB7LGAkIE6OrCF0DfFnmfOs7ajLDAy5Qwvh5M6e9CU5eV3Ub6Rsv
         apqQa/EEzPWmof+vmQrLFwjZ6/ZjrqzMyssKoWY9KuSrzldn3le+yuf9bNclknn29iU9
         SGU+KmTpqbiAEDgFHy2tp/GAJnM6fCnF00VZWpayH9iI+QZUj+llply3Jny+ZXCHCWnq
         6fBGX7JlXHX0x1T7Ft+pGeyLyEANQLcj/MK6ANLOW3hUvv90D2y0k4akdICEo3Iux0ID
         XZNEIDCXcmtEJDKPU/NM0u8Rzh5IaZnJsSyTUk5Peuus+hPvB4PQUTtRbGjds9A3AEBU
         vQog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=wRZ/7faq6GOoPBYzL6BE77RduU7s1Ve9QnA7WCpWQfY=;
        b=hquHec5EkODfdMh+WWV+UlUwqkX5vX5V8e1h5rrGD6qK12Lk4w5kvnnnSoF+vx34g6
         3su5YCc++wY/6jf3vUE+LG4T78VZR8zZ2e7x9HElivT0HdzZsncd6dbCUGgvasU4i+l4
         Ir93Zn+OVqyPENCVhpB1aoAN4x/ZbVNszzXeWqoxGgoF4o2NX7MdsqPqhReRrDvRHe64
         cvmmmepZs4k2ehMiDjN2LSbzsAqGFYY0GXDY0jprFgygeXXwHc0rnvZY+9OQq1WalNxR
         PuPBpmA6FkavF00qG4Q6IEEoJK61tIymVHufbjlX99XhRKmg2RVGvFnZgI/xKO1UQooN
         reVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wRZ/7faq6GOoPBYzL6BE77RduU7s1Ve9QnA7WCpWQfY=;
        b=BB08dKHk+i2fApFFvIxYHJ7k50CDlAkUiUbPkwTl5QJJavY3XwMoHo1FIzNfMzHoR8
         ZN+72q66C61akb/FVPU3yNWFd0cyIUozMjLpRwiiP/V9vSguJqhblbHIU+h4+9FOtwFe
         g114uDxawEK6Yaf/65mZWZ+7e8TgurJiHQV8t+EdCesgx6SHE9LuT7VQs1kGjMXFAPUr
         n5W3r2LcZ8TEZkI4WsKUqd66j1jJwXTChRvJzvHb1Zl0pVULrZ4loX0Oam46AnndXr2u
         udme6GT/hF7BcY+3L6DyKmWUcqILpXYcQbXVSbV0Ng4o12xEIBZQ8zDUynBxbk3W11G0
         XiCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wRZ/7faq6GOoPBYzL6BE77RduU7s1Ve9QnA7WCpWQfY=;
        b=QqzXrjq2MsHptfMYiesQwgh25TJj4N5GmtBTzzEktgSxEuFuskqkeee+D/enMXDJJa
         JnNWZqPX3Pe/jszWCrwQy7tPblavFMFAMTae3LJ83uFWEnItLfB+yB5DTocc+aiBgLH8
         RVhMECBJ+HDOVXHFGX8bvbDSrFf4tf+jvPX/mhaQuoG+Z4+BYFiSfvbjpxzLxte0tMzg
         D1cYm35+kR/av8tbFtcFOg7sg2kaQ8SGlVMlPgMPtBcmBAsO1Ahyc6rbm7yDpLZuX0iI
         pGscCN5L6pBzJcnalQa+y3KXnfRwseC6xr7SvKkErp2Lle4yESJXQYbcb5AmPuN/2Ei5
         m/lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWuvc1Rsj+HWMPS5MJT9pLdfZFzbYw7Z7j1jllkr7Yvp7+1ojYW
	QJNzpYzIox1NGUZ00mJzRws=
X-Google-Smtp-Source: APXvYqziUH0zd9iDtu8sGEf/MOSG+AbgxWv94NGv8hPkdRuv6eIiX2vYyNeZNnPFbk7GLvnYaXV37w==
X-Received: by 2002:a2e:b0c4:: with SMTP id g4mr1659264ljl.83.1579166435638;
        Thu, 16 Jan 2020 01:20:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8592:: with SMTP id b18ls3006506lji.13.gmail; Thu, 16
 Jan 2020 01:20:35 -0800 (PST)
X-Received: by 2002:a2e:a486:: with SMTP id h6mr1713731lji.235.1579166435046;
        Thu, 16 Jan 2020 01:20:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579166435; cv=none;
        d=google.com; s=arc-20160816;
        b=heuW046x+ZDi3Q82LrmQlpqEb6me6XXRqquqOFrtZAUYHnbzcnfo5Nj9CSFCoMGlQ0
         C+FvIh3HFxRAivqvCWeM2EfLW0VLiEOjwoUUFt5I2wEghqCdVrDcPdnEt+8hoVkchyyQ
         +E17lZR0lNc3AmH/NKaEdPqX1jhL62h9r9Yl3Igrr5Qcgw/47Rjyq0VaP67T3nZ0PLTq
         VLjSisISoF/MRmf9Z3ODOHtzSdiBl4S8QFJFq5CExM0/XJMKA1Rf9KPM7or2ZNk5quoY
         qu7+quARqH5AtoIoFhdC8X2eJCd5Kj6WXAx2uzqpnclAIMZVVQcPztAlXC1m2Jt/ds2Y
         06Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=cCrKdUykToj0LjfqGl+8hrXiC1ZmRNpjtmlrLsCbgVM=;
        b=rl5rxr3KzqkecG5FxEyl11Ry4Y75YVkwg1Eeq/0jQ1l7k5oFjn90iuW9ti6RAItU/C
         GBAsRTvyiqvAtoJiFSK/+qz18N60mv/GZlCcPeyalFxnmjvg5xXXpfqQyHgJkOnq+yb9
         Jt5CD2ZcDNpfVolgNVt/9gCsm/E1p0wadZJnue/032oEDdvI/zDTqH0ZpSzffnFJJlOL
         NMVqPm1ZCOC/gmDH1WEHT1X/AukvipX6JK+1wv/T0341rC5wvv4vR8S0oMrWW2sORfwi
         HAyMTPkbnMWXVf7qxP3KDsX4SZ8vJ3ESZLe1dzOw1fYJ3tv/utHkmItG4AYwF0WH5mTP
         D3vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id o193si978948lff.4.2020.01.16.01.20.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Jan 2020 01:20:34 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1is1KF-00BgMa-LC; Thu, 16 Jan 2020 10:20:27 +0100
Message-ID: <2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel@sipsolutions.net>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Richard Weinberger
 <richard@nod.at>, Jeff Dike <jdike@addtoit.com>, Brendan Higgins
 <brendanhiggins@google.com>, LKML <linux-kernel@vger.kernel.org>, kasan-dev
 <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org, David Gow
 <davidgow@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
 anton.ivanov@cambridgegreys.com
Date: Thu, 16 Jan 2020 10:20:26 +0100
In-Reply-To: <CACT4Y+brqD-o-u3Vt=C-PBiS2Wz+wXN3Q3RqBhf3XyRYaRoZJw@mail.gmail.com> (sfid-20200116_101838_954522_B05BB78D)
References: <20200115182816.33892-1-trishalfonso@google.com>
	 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
	 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
	 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
	 <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
	 <CACT4Y+brqD-o-u3Vt=C-PBiS2Wz+wXN3Q3RqBhf3XyRYaRoZJw@mail.gmail.com>
	 (sfid-20200116_101838_954522_B05BB78D)
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

On Thu, 2020-01-16 at 10:18 +0100, Dmitry Vyukov wrote:
> 
> Looking at this problem and at the number of KASAN_SANITIZE := n in
> Makefiles (some of which are pretty sad, e.g. ignoring string.c,
> kstrtox.c, vsprintf.c -- that's where the bugs are!), I think we
> initialize KASAN too late. I think we need to do roughly what we do in
> user-space asan (because it is user-space asan!). Constructors run
> before main and it's really good, we need to initialize KASAN from
> these constructors. Or if that's not enough in all cases, also add own
> constructor/.preinit array entry to initialize as early as possible.

We even control the linker in this case, so we can put something into
the .preinit array *first*.

> All we need to do is to call mmap syscall, there is really no
> dependencies on anything kernel-related.

OK. I wasn't really familiar with those details.

> This should resolve the problem with constructors (after they
> initialize KASAN, they can proceed to do anything they need) and it
> should get rid of most KASAN_SANITIZE (in particular, all of
> lib/Makefile and kernel/Makefile) and should fix stack instrumentation
> (in case it does not work now). The only tiny bit we should not
> instrument is the path from constructor up to mmap call.

That'd be great :)

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel%40sipsolutions.net.
