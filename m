Return-Path: <kasan-dev+bncBAABB3XFXL7AKGQECM2UDLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AAD72D1DCE
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 23:55:44 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id v138sf4931689pfc.10
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 14:55:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607381743; cv=pass;
        d=google.com; s=arc-20160816;
        b=FZKumXRc+qdPIHNqtTKHCmsd05EIeIk6m9uQdNNnxEodYiwDtXfN6yxrWm/6Q2HjbT
         461UPh2kp8+NESB5Dt/xNwNpfz2UyrCgUiYpvv0M+jXU8Bvi38sovhaMb7opG0srbYCz
         6sFMUK8lVVaOtDjkXNJqgNUI0pxtkfy+mM5tTas7QU/u7hPwxnwj77R7ZZsg0+n/OyyG
         XIjDiiYZiVjFHDnhtiwqoJbOVQTjfLy7t1U65dlc+s04fHKSxyZxX+hG8mx+anAQMaTR
         EBUl8sRynxUQHBF3KdcnHgQgiqeXkE2yWRNr/cjL1ibO06xsJtIzWuV3upcvpxghWRb3
         O55w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=bam+92iJLlraJtSXibm+bWIxB2rxW0bhsMlGHkVVyF8=;
        b=nOpgE+HAK4ilK9nuMpiEmkgJvimaezovrxrZkQcbBP5Znpi+GIJf8m1eW00zDEoHIm
         pWSgUoHItCD20SHVieB7j/WvDM095NNu+n5/ANuzVph0R8nDnvjDNFxOZBLcdH0XSQHJ
         U1ZFzZiZ4a/AT0sBbVG2ZhPHlPbtjsk6Eo8ANWBcCZQWmkBuWVtzplDleRh2jxdvTqxn
         LlGvPLqhu/9KQTsEViXwm5qLHOvLWwFJxiOIyqZoILtuE9NW5iGUDKc2VvtJ1Sfya2xz
         gYz4E3In0/KTQIotNCfJpyIJ1eL8KLG1qYtQ55pKCQguZfCSMA4ikoA0WeFtX3zBDyvE
         VMpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HzKGZEMu;
       spf=pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bam+92iJLlraJtSXibm+bWIxB2rxW0bhsMlGHkVVyF8=;
        b=AHhOI/CCIebqMbx2M99zViE9g/Dgh1Py4lwZ2i7D0k6UsLOqjt1wiYZ1CG4+JiAU/R
         Edl+6Ntbjv6quuCGpPaXA4ytQvWDDE6KjkdL9oEW7I4w2p4SfHwP4MJubuKyVZYW4Nri
         vyeJWY+nvTAvWLalMedwh9eyX1NpZcaWKQqjCvWLbZjoZUnIJG4+WxW8B5NL9qqzbocx
         TMJvHBjSiu+AMBvWk0/fs+0R+BmE8kYE6RRYGZ2Xv1ECVuligelOPcv+uU0k8v93hUeP
         2DMGiuk9CHHNubFR19Nsi3Ubzs4OKYo4tzgg4j37OjysI8e1qgw5AAdgsaukKQbn28t8
         2EYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bam+92iJLlraJtSXibm+bWIxB2rxW0bhsMlGHkVVyF8=;
        b=PLs8n0NTlNo4BXMbY5pdpyl0KqArSPkKaCikXDi0VYQqsTTCeHCbhy2VpJR7z/6/Q5
         t5fbg9Tjd7h7yjc5XUB2puagG+KtsKD6Xjmpq4AECzc0hY7zpTwTPBlwFqPcl6v1ck+U
         Hxh8BkrnMkZPx/FRo7OgDS4yy20JiUKW8oW5svCFj4PH7I3GqGaq5UfUiBeCuC/FVV8H
         ra/RaDY/O+W8/KimWCV3hiDIJ6xrGRDpEhGg8cxn08zXZvH/v3OROBPx6YCsn7LOlxw8
         SLMo8JbkH/GMHPOhlag4dv9Y8ANzmbb4H3s+jHj9pUDtOc94//6UjzS4MGMC2DeN9plA
         pJNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GgZskJzNnLhHByL7dK9i3PGvvwAX0TPkvL5R0zAhV6Rn9Ngy8
	ItJj5HHyHsQYF9OTNzxb1RA=
X-Google-Smtp-Source: ABdhPJy2o6x2np+ONsQs2OYYwrx2SpefGqYkhv7HJDq/LKKQGlZT+3ZylYvrlaYNs2pDCdfvb9+adA==
X-Received: by 2002:a17:90a:7501:: with SMTP id q1mr1008788pjk.46.1607381742987;
        Mon, 07 Dec 2020 14:55:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c205:: with SMTP id 5ls8801283pll.11.gmail; Mon, 07
 Dec 2020 14:55:42 -0800 (PST)
X-Received: by 2002:a17:90b:4b07:: with SMTP id lx7mr1029398pjb.230.1607381742561;
        Mon, 07 Dec 2020 14:55:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607381742; cv=none;
        d=google.com; s=arc-20160816;
        b=bsCHfWy9GMkE1I7QRWCRIEVnFzo9kRCUUUEd5irkG5aW3+Ds9cPEvsPGepoWhScSeX
         GX18weJ5MbTRf7ySUyl+k92jrKGr+iThDPCb2yJILYlIRwOpF+1lLG4jsmMx4KhIbFE4
         hWHgm8Y6v8OhV/M5vwabEEBofMQg8Ky98DL4jaCMgGShvE0sG8wMCIl97Oi9ji80Ifd8
         JTy5axVj5Fixfyf3icB9d3lwMggkd/M5ut47pwg3NNXWcvDeGjDfHWcmG2cwQVuz1Pmc
         iP6nw4R1GJ9WSX4zG+fkJMx0DCCJkyn6CpFruU0GOz5PQ3h+eVKgPQmwckPgoTUKh6MB
         y/MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=q5M5M04DlhaxB6oIqV3NhZr666HtPW8APzFV0hPj5As=;
        b=gL5WsRV65ChYdaLDS3Zz0S9P99wmmh7imlqg5FFh33KhTSzYJis/XXrChRz+I79CuF
         ErVgflBpJQtu0mCTilgSeIfWnnmgXcBygYDJGzEpnovYZGZRmKrziyBZi6sGr7LygLJb
         +4Yb4+u8WUJGjnwiYE6Baf8LQjTxPkDikr9OZLyooofd6BvXEBCHZRNsBrpJ5sbwBEqS
         yydYAxjq6wIveo5ZVkdkYxN6hxmNSAyNYRzbsLmW43egISAI0sFvLqQVldkmSeh33kVd
         uA1XGODOGTBsFHIuNUVntLXgNK9KQdqY1DXXdldz12T1aP3HAWZvm8WK7Jge0XoQksVn
         twpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HzKGZEMu;
       spf=pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b18si634077pls.1.2020.12.07.14.55.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Dec 2020 14:55:42 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Mon, 7 Dec 2020 14:55:42 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com,
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com,
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
Message-ID: <20201207225542.GM2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
 <20201207194406.GK2657@paulmck-ThinkPad-P72>
 <87blf547d2.fsf@nanos.tec.linutronix.de>
 <20201207223853.GL2657@paulmck-ThinkPad-P72>
 <878sa944kn.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <878sa944kn.fsf@nanos.tec.linutronix.de>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HzKGZEMu;       spf=pass
 (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Dec 07, 2020 at 11:46:48PM +0100, Thomas Gleixner wrote:
> On Mon, Dec 07 2020 at 14:38, Paul E. McKenney wrote:
> 
> > On Mon, Dec 07, 2020 at 10:46:33PM +0100, Thomas Gleixner wrote:
> >> On Mon, Dec 07 2020 at 11:44, Paul E. McKenney wrote:
> >> > On Mon, Dec 07, 2020 at 07:19:51PM +0100, Marco Elver wrote:
> >> >> On Mon, 7 Dec 2020 at 18:46, Thomas Gleixner <tglx@linutronix.de> wrote:
> >> >> I currently don't know what the rule for Peter's preferred variant
> >> >> would be, without running the risk of some accidentally data_race()'d
> >> >> accesses.
> >> >> 
> >> >> Thoughts?
> >> >
> >> > I am also concerned about inadvertently covering code with data_race().
> >> >
> >> > Also, in this particular case, why data_race() rather than READ_ONCE()?
> >> > Do we really expect the compiler to be able to optimize this case
> >> > significantly without READ_ONCE()?
> >> 
> >> That was your suggestion a week or so ago :)
> >
> > You expected my suggestion to change?  ;-)
> 
> Your suggestion was data_race() IIRC but I might have lost track in that
> conversation.

OK, I am inconsistent after all.  I would have suggested READ_ONCE() given
no difference between them, so it is probably best to assume that there is
(or at least was) a good reason for data_race() instead of READ_ONCE().
Couldn't tell you what it might be, though.  :-/

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207225542.GM2657%40paulmck-ThinkPad-P72.
