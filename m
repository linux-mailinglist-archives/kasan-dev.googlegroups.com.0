Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH56YDYQKGQELQEI4XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B70C14B3B6
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 12:46:40 +0100 (CET)
Received: by mail-yw1-xc3f.google.com with SMTP id a190sf10314461ywe.15
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 03:46:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580211999; cv=pass;
        d=google.com; s=arc-20160816;
        b=YGruxCW54/dUixdrsEs75QqKHKwC0XsaTh9+XWsDI1S0Kmd2uOgAiDOrpWFkQ6dF5y
         tpZ0dKHbGO6OxKLoHPAH8GveqaYeGlHBUdnxOQ7SLW7M50S9ZAi/urRFM98VnrWTH4mc
         DLsT7c7Xk4kjLwhetud+ymYC0UGJTl3LKQnBcpqbHo3rRLPKd28gV96MhVO0YNYz793P
         Z7WKNtyUxZem1eTvjTEMnRPVKzMgRb5osKy6c4ra6bzcQ7/RVuijW1rjirhbXnCbRMn5
         +NfhciNdScK7BZ+5xzahwC+IAqvZiiCmAOxcfQ5D/aXiBnM+/ZXyw41fHxyrId8cktnd
         yuKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cAZV+fFaFt7EJEfsQS3JGnFUGGu1BphC6L7Ztn71vz8=;
        b=H8k9p5kBY4yTw1Wf6DoEVBWNlEx6GR54j0sW8BwF/fkddeHB7HKLk3VIQF88nLtV0D
         e2FtGOeTn9PkwrFXyq0Eom3WuCa2psRuvViKhWog3QLDAoai0yDquhP7x1zXCnStuKxd
         9veF/CBNIBH63rxg1OkcsuCphVm8UDNjJWFcE+VQWgh97GM22qrWtCLxFjTRglrcCXVt
         dReBb0LC02A5x0dmknm0h46u7rBdIsbL2qxGHgfaaWi5Y6JFkJFrWRjKDNB3DGlff0jx
         tgJ9ZAoDsI/QL9oCLtJtlPstnn3/IWOi0M2SWS0b9sW0cZqRLk64ay/JtlgoOkFVFSXv
         iFeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZttBa79g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cAZV+fFaFt7EJEfsQS3JGnFUGGu1BphC6L7Ztn71vz8=;
        b=i0zH3zvi9d7q9KPAqqThz0ZsMHEwzi09/3vkCWH4WknoGDUaiGQmmenjQsPsQnCqT+
         1gvwztnn8hHAqXPTmk0m/RR/234DRNLmM4JDNrpOvL9Lm3D7dGUTQxmS/lJ1pnXhaRgY
         6aaotiG1tt1+jTt3NGHA4JQe+pWIWAtqi/XKko2rBdg57d4Vn9Au/xkoD92EB8AjXBP+
         jYGUFToVnQw9RMb2tGxj9Xe6e3kAsQNQm6H+Q4TcHXsBzHrHFTLrPBm35L5tHY+lj9ZE
         0X8jWcTJ7aPvs0FBlpzb1RJiK89gNG3NvTZKkGsGEdqrWRSCWNzLQ7Muznw/vCLvdJDh
         byqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cAZV+fFaFt7EJEfsQS3JGnFUGGu1BphC6L7Ztn71vz8=;
        b=EqXQC5qjhUTAkCB3k2U0pmPa8DzgR74V9ewt1IihvDAdC10MAIoSCTUHIIPlIyPSW3
         bqJQ0pLK9GYljYScPdgL9nxCj3LmH/IXSFDbcmy3Yf3qRMDijTgtBeeyo1FeeXlk+kn6
         XFTm49RrFX/XEQaA1e7JU2d7rIWPZQfboig3464DJlVsflXH/gfsbH1FvIw1QBPQgVpJ
         B9fvHpWPmDXOnXPY3LVyQmHnVYV3vQP2lKwL16t1MAuomIf6LP6uxlHhMyg0Bz23M/aG
         tGwyoLpOGrxzv2zXGWfKjz54eGRpmd6WuXC3KWhL6pINvQIy9lIbKoJcDuuVbyFGYwdy
         FbAQ==
X-Gm-Message-State: APjAAAUKkz3a9KUHGuw1Pw2iKOQJWpVdI8XPDyg0r2ElgInHqDkWaOGD
	EK3ML0xSyRlJE86Rg6SawFI=
X-Google-Smtp-Source: APXvYqwj6mn3qtYtzPtllEbHiMKfSbDoax4WUknsZ1De1fQCzX7pP6gcZxslOmWJ+ct96w1RKoYefg==
X-Received: by 2002:a25:cbd1:: with SMTP id b200mr17736385ybg.234.1580211999287;
        Tue, 28 Jan 2020 03:46:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:cc05:: with SMTP id o5ls2648123ywd.1.gmail; Tue, 28 Jan
 2020 03:46:38 -0800 (PST)
X-Received: by 2002:a81:924d:: with SMTP id j74mr16323986ywg.381.1580211998846;
        Tue, 28 Jan 2020 03:46:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580211998; cv=none;
        d=google.com; s=arc-20160816;
        b=k3C6LiOAt9ptNo3pxZAXGf99xK8ODgcbVTtQwxwzw54EfN1Np/SjOSxHIlg7QIq54U
         5grj8DkI+Pm46TrxcZUzu6xzJnQdTz1veCFX1fL4Znqk0OBbUevglun7Dx/MvglUtIRC
         4SbtaXx2fejx5CGosXwOQp2huUcfrmvxeDg8Sdh2yim7Zoub9STkIGNYXyOCD99zMB9u
         kRh7r+s7mucMCkbAgCAiuN7zHTRbN5DooViivzSxTrEBiFmwgghEUGzXNrCGUooJNVyO
         ATT+0YRDC2Eh1Twd641+NajD8HFsoeKOlYsDgsFBsjfCQFUt5GUb4gjXEnyiDyM2QnkA
         /8PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1m2tU4RYYXkdt6z78fcFtsSj6N8xIeX/v5Mckd3HuOk=;
        b=X61lr9T3v88tQm5zMGgtld51+ZTRChFDuH20nkb8Mdxn1sHcOVXnYPFNkbNby/lHZz
         zOxY2k2MR4+QF3hZQrHm586aTn2LLSLDJlSpwbN4x1UIQ2ttTM+XSX8N8XYQ0hU4CV04
         jPwVtCTJttS+x0pveM8fz+x+9Sw1c7Uv2HVhh5/qa1YYp9N+l7XUmBdpFxqDMd2hEfGx
         RA/lliApxsUTADzgLhkYbJzPoxF/4xdD04G22+K+gQOAFCS9wKXTdIJENjz7hkm3G6Z/
         pBLk7wmlZbnqAKoDbp1u6j5B1ENBzRy6cUVwVID4ptdlBcUlc9gi17iYTZtZVry+bHj4
         6zhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZttBa79g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id i200si604120ywa.3.2020.01.28.03.46.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jan 2020 03:46:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id p8so11654733oth.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Jan 2020 03:46:38 -0800 (PST)
X-Received: by 2002:a05:6830:1d7b:: with SMTP id l27mr14982490oti.251.1580211998038;
 Tue, 28 Jan 2020 03:46:38 -0800 (PST)
MIME-Version: 1.0
References: <20200122165938.GA16974@willie-the-truck> <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com> <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net> <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
In-Reply-To: <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jan 2020 12:46:26 +0100
Message-ID: <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
To: Qian Cai <cai@lca.pw>
Cc: Peter Zijlstra <peterz@infradead.org>, Will Deacon <will@kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	"paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZttBa79g;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 28 Jan 2020 at 04:11, Qian Cai <cai@lca.pw> wrote:
>
> > On Jan 23, 2020, at 4:39 AM, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Wed, Jan 22, 2020 at 06:54:43PM -0500, Qian Cai wrote:
> >> diff --git a/kernel/locking/osq_lock.c b/kernel/locking/osq_lock.c
> >> index 1f7734949ac8..832e87966dcf 100644
> >> --- a/kernel/locking/osq_lock.c
> >> +++ b/kernel/locking/osq_lock.c
> >> @@ -75,7 +75,7 @@ osq_wait_next(struct optimistic_spin_queue *lock,
> >>                 * wait for either @lock to point to us, through its Step-B, or
> >>                 * wait for a new @node->next from its Step-C.
> >>                 */
> >> -               if (node->next) {
> >> +               if (READ_ONCE(node->next)) {
> >>                        next = xchg(&node->next, NULL);
> >>                        if (next)
> >>                                break;
> >
> > This could possibly trigger the warning, but is a false positive. The
> > above doesn't fix anything in that even if that load is shattered the
> > code will function correctly -- it checks for any !0 value, any byte
> > composite that is !0 is sufficient.
> >
> > This is in fact something KCSAN compiler infrastructure could deduce.

Not in the general case. As far as I can tell, this if-statement is
purely optional and an optimization to avoid false sharing. This is
specific knowledge about the logic that (without conveying more
details about the logic) the tool couldn't safely deduce. Consider the
case:

T0:
if ( (x = READ_ONCE(ptr)) ) use_ptr_value(*x);

T1:
WRITE_ONCE(ptr, valid_ptr);

Here, unlike the case above, reading ptr without READ_ONCE can clearly
be dangerous.

The false sharing scenario came up before, and maybe it's worth
telling the tool about the logic. In fact, the 'data_race()' macro is
perfectly well suited to do this.

>
> Marco, any thought on improving KCSAN for this to reduce the false
> positives?

Define 'false positive'.

From what I can tell, all 'false positives' that have come up are data
races where the consequences on the behaviour of the code is
inconsequential. In other words, all of them would require
understanding of the intended logic of the code, and understanding if
the worst possible outcome of a data race changes the behaviour of the
code in such a way that we may end up with an erroneously behaving
system.

As I have said before, KCSAN (or any data race detector) by definition
only works at the language level. Any semantic analysis, beyond simple
rules (such as ignore same-value stores) and annotations, is simply
impossible since the tool can't know about the logic that the
programmer intended.

That being said, if there are simple rules (like ignore same-value
stores) or other minimal annotations that can help reduce such 'false
positives', more than happy to add them.

Qian: firstly I suggest you try
CONFIG_KCSAN_REPORT_ONCE_IN_MS=1000000000 as mentioned before so your
system doesn't get spammed, considering you do not use the default
config but want to use all debugging tools at once which seems to
trigger certain data races more than usual.

Secondly, what are your expectations? If you expect the situation to
be perfect tomorrow, you'll be disappointed. This is inherent, given
the problem we face (safe concurrency). Consider the various parts to
this story: concurrent kernel code, the LKMM, people's preferences and
opinions, and KCSAN (which is late to the party). All of them are
still evolving, hopefully together. At least that's my expectation.

What to do about osq_lock here? If people agree that no further
annotations are wanted, and the reasoning above concludes there are no
bugs, we can blacklist the file. That would, however, miss new data
races in future.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNo6yW-y-Af7JgvWi3t%3D%3D%2B%3D02hE4-pFU4OiH8yvbT3Byg%40mail.gmail.com.
