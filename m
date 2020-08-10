Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBXV5YX4QKGQEAKJR7UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id C85DB2407DE
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 16:51:11 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id c2sf6864603plo.11
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 07:51:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597071070; cv=pass;
        d=google.com; s=arc-20160816;
        b=ybe/BaaD5l4p4juB8rjHMt/AZw0YlQlOAugYVQz2E56KqCMpOCD4qWzyBs+Gz8Xl19
         KMedGC+E7F8dFd2u4QJF/+1aSrBJLJplzem6qDLGiHCnseOi2vzJEWHDT0NZgyuOtzBC
         9bNc4bYoSrG1ZLFivsgiupVr7WTKxUgX/veoZxsbwDSNAMI5sHrzd2fDMyz4dwK7HrLV
         5PCLu69NTEcFgTN8LQxXto9zdYOELTWerpxH1xCA3diVXIrqp04oEXA3PSQU3NLL2s0v
         DPqblbj76jmGsl8fslAhdlQrpsGkMag9qfpeS7x5d9goi1DmVAzu9zwvGY58nlnzh4BO
         Qf7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=IEWJo3/odinaSwGMb8hXzQj6t+t+PCslHP63tFT4qi4=;
        b=Yn29mXCSvTEqjzBvrWhwwj645lCZU0C2LsflqSZaJ+Cg43uoN3GUatjI8ZqU7Nhdj/
         nS2SJFJ5kyqMhclF9cQB/O48OfwkTD8DGm1kWKXg4Ej/KIz1K79uJjXudJYPiRu+MhXh
         Iln3XdFaggv4WEbMkvN3W666p1AaZ9he16qFtLPXnAjjltTegFXdha//2/9OnQXa5bkn
         g1HDySNfdwFc8/rxvUpEC/Y+LcmFhz3cUkSit/BHMSB7tApkxGJ4cxEpUY/dPiNmjc9R
         92d5RsK9BQaWrhRJhQmTPOsP25wDIdQOG/51HsBEyElUGdomMjEHhZT5/Hd+T5mAiKnm
         1rGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Ole9foJp;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IEWJo3/odinaSwGMb8hXzQj6t+t+PCslHP63tFT4qi4=;
        b=oSLQODTmukwzCLQalThc+bropjZ1JK8jKBrx49RY5QqLDt6WBypVU/rq1+UQDobS0k
         P3NU6zIVc6ClkdPFrMEnwMNidiaET7KYV1yrGaAwaFUXdmiPcuwJj4ZHgx7Smjq8zzur
         g4XsyhwiAc2Ce12En9NViu4WBlxCKUWb43feo3VDO8oWwMKug9qs598Cc2hbvdoJ+XV5
         pfFFvwNAWDGgTB2u/4dXr79ft4dxNparr98D2zwAqkq9FHYMjRymriYK9BWgRg0Nd3dW
         BFafIOywviK+5q3UIB32mOqyOtXInFlHKv4O/NTJbwP9oZtTgqlvuV/Vaz42TPA68zme
         KkWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IEWJo3/odinaSwGMb8hXzQj6t+t+PCslHP63tFT4qi4=;
        b=Odzv91+yESwq9wO2msRDS6BkHG2Gl0lusVRX7FnQKJ8LiZfwypUXkWOqCFaV7ZvA52
         5/KFOm5wpylnwastrgCC235G58yO3VcURZtPXRQXW2HduCrWtD9XsJQ2n1mr7q+5V3b0
         Rxnx2BFCpQAIGD6D0XQSeYo/uaTr+T/gp+SJRodxrri24VB8TJhzvjP7G4OeDyu4btI0
         Gd1rXn8lFBl6kGnIU9aZ2iizbOmKfUVvgKucFIwi2c2pr2SMShl8y5KZ/jRpKvRNCmWv
         pstf2SVnWu7dpxHzQ85sLVN5WJumeESBE9PE3Eu3jmIzt9I6bSf5DiRR1BQSnN4tWYma
         u4Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533meGQA7M9IcVnUzOMhk7Z6nXDA9wGdc0PFHBMF/ktJfHj+QPtH
	5jWs+a1HMvOfrhjx55LeXgA=
X-Google-Smtp-Source: ABdhPJxbfbAqhAa4apFA8S7GCiDxDdvnKQOm2YXjURRdypXqmngdXzN/iq9jbgMO31ROmQnCWtnCqQ==
X-Received: by 2002:a17:902:780f:: with SMTP id p15mr25517222pll.56.1597071070418;
        Mon, 10 Aug 2020 07:51:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1988:: with SMTP id mv8ls7020854pjb.0.gmail; Mon, 10
 Aug 2020 07:51:10 -0700 (PDT)
X-Received: by 2002:a17:90b:23c8:: with SMTP id md8mr28622016pjb.176.1597071069925;
        Mon, 10 Aug 2020 07:51:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597071069; cv=none;
        d=google.com; s=arc-20160816;
        b=U9jryGmEvfCu0ozkykrYezdoUUK13Y/o5xzqPlDUE/+b/7+bpZK+W/Ja6tTPzOacZr
         A/NT9GLD71dCL2dt+l5msSlNK5b7/1W6rJmVSuCGIudEk7aa/XGN4kpuUAF3Y8nX5dzb
         nPGgUXew9kfu74kn2cAQWQPgJHYEupNw4mPK7taNlwUtNk8dgMslsOv+XeCR/+IRIe8P
         1wy+HywnPdUxA+1ETyn1UmfhhjUFcjDJGm3ScHnpmTsQCPv7ll0QhezXKCARMx6+p+Ol
         sGjswHAeFsTzEhf8eaRgYN7+N8RjxOG3+gSLEAJKWm9qBdE/mwP5tzbrMbcyI0uX5LQI
         1fbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4aZ52qCxnYvMfbknflPb2u1mseuw+l9ZuJed3m/JJv4=;
        b=XJXu82J28rGuJT+V+0r2dKf60L/DbDLMpjtbv7lQiY9a8PQmdlcuNkK766NUSQC16Z
         ys/wAqCO6Q26eT8XMea1L//ZO7ZgZLgczyg0N5d1B6etzA3UCSX9oN3NjXI6SI9nGR6o
         LLirXzJP0n6mejc0NhJvwVdNJPJQ2Bh7Z+q+J1AVY2xa1M/KXVGt7e2FcQpbKNWxvbLR
         JTPSx8WqHVBUAO3EfjkbIzeUSRE3FTC/NXJlxwKnk5cXD2Khz1YFqm+3XY1NzvyReIGu
         jOQPBYC+adfzX/NhAP3OpzmMYmW5etZw5JA48qynS7f0k/+E3Dx8Bj9bAaK9eJEkbQvJ
         jf4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Ole9foJp;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id n2si1331171pfo.5.2020.08.10.07.51.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 07:51:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id b25so6922338qto.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 07:51:09 -0700 (PDT)
X-Received: by 2002:ac8:5685:: with SMTP id h5mr28435277qta.378.1597071068740;
        Mon, 10 Aug 2020 07:51:08 -0700 (PDT)
Received: from lca.pw (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id g49sm17027037qtk.74.2020.08.10.07.51.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Aug 2020 07:51:08 -0700 (PDT)
Date: Mon, 10 Aug 2020 10:51:05 -0400
From: Qian Cai <cai@lca.pw>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	John Stultz <john.stultz@linaro.org>,
	Stephen Boyd <sboyd@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	wsd_upstream <wsd_upstream@mediatek.com>,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH 0/5] kasan: add workqueue and timer stack for generic
 KASAN
Message-ID: <20200810145104.GB5307@lca.pw>
References: <20200810072115.429-1-walter-zh.wu@mediatek.com>
 <B873B364-FF03-4819-8F9C-79F3C4EF47CE@lca.pw>
 <1597060257.13160.11.camel@mtksdccf07>
 <20200810124430.GA5307@lca.pw>
 <1597069882.13160.23.camel@mtksdccf07>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <1597069882.13160.23.camel@mtksdccf07>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=Ole9foJp;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::843 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Mon, Aug 10, 2020 at 10:31:22PM +0800, Walter Wu wrote:
> On Mon, 2020-08-10 at 08:44 -0400, Qian Cai wrote:
> > On Mon, Aug 10, 2020 at 07:50:57PM +0800, Walter Wu wrote:
> > > On Mon, 2020-08-10 at 07:19 -0400, Qian Cai wrote:
> > > >=20
> > > > > On Aug 10, 2020, at 3:21 AM, Walter Wu <walter-zh.wu@mediatek.com=
> wrote:
> > > > >=20
> > > > > =EF=BB=BFSyzbot reports many UAF issues for workqueue or timer, s=
ee [1] and [2].
> > > > > In some of these access/allocation happened in process_one_work()=
,
> > > > > we see the free stack is useless in KASAN report, it doesn't help
> > > > > programmers to solve UAF on workqueue. The same may stand for tim=
es.
> > > > >=20
> > > > > This patchset improves KASAN reports by making them to have workq=
ueue
> > > > > queueing stack and timer queueing stack information. It is useful=
 for
> > > > > programmers to solve use-after-free or double-free memory issue.
> > > > >=20
> > > > > Generic KASAN will record the last two workqueue and timer stacks=
,
> > > > > print them in KASAN report. It is only suitable for generic KASAN=
.
> > > > >=20
> > > > > In order to print the last two workqueue and timer stacks, so tha=
t
> > > > > we add new members in struct kasan_alloc_meta.
> > > > > - two workqueue queueing work stacks, total size is 8 bytes.
> > > > > - two timer queueing stacks, total size is 8 bytes.
> > > > >=20
> > > > > Orignial struct kasan_alloc_meta size is 16 bytes. After add new
> > > > > members, then the struct kasan_alloc_meta total size is 32 bytes,
> > > > > It is a good number of alignment. Let it get better memory consum=
ption.
> > > >=20
> > > > Getting debugging tools complicated surely is the best way to kill =
it. I would argue that it only make sense to complicate it if it is useful =
most of the time which I never feel or hear that is the case. This reminds =
me your recent call_rcu() stacks that most of time just makes parsing the r=
eport cumbersome. Thus, I urge this exercise to over-engineer on special ca=
ses need to stop entirely.
> > > >=20
> > >=20
> > > A good debug tool is to have complete information in order to solve
> > > issue. We should focus on if KASAN reports always show this debug
> > > information or create a option to decide if show it. Because this
> > > feature is Dimitry's suggestion. see [1]. So I think it need to be
> > > implemented. Maybe we can wait his response.=20
> > >=20
> > > [1]https://lkml.org/lkml/2020/6/23/256
> >=20
> > I don't know if it is Dmitry's pipe-dream which every KASAN report woul=
d enable
> > developers to fix it without reproducing it. It is always an ongoing st=
ruggling
> > between to make kernel easier to debug and the things less cumbersome.
> >=20
> > On the other hand, Dmitry's suggestion makes sense only if the price we=
 are
> > going to pay is fair. With the current diffstat and the recent experien=
ce of
> > call_rcu() stacks "waste" screen spaces as a heavy KASAN user myself, I=
 can't
> > really get that exciting for pushing the limit again at all.
> >=20
>=20
> If you are concerned that the report is long, maybe we can create an
> option for the user decide whether print them (include call_rcu).
> So this should satisfy everyone?

Adding kernel config options is just another way to add complications with =
real
cost. The only other way I can think of right now is to create some kinds o=
f
plugin systems for kasan to be able to run ebpf scripts (for example) to de=
al
with those special cases.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200810145104.GB5307%40lca.pw.
