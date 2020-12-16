Return-Path: <kasan-dev+bncBAABB2HZ5H7AKGQESSJN74I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 387392DC85C
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 22:32:26 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id z15sf7821106vso.23
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Dec 2020 13:32:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608154345; cv=pass;
        d=google.com; s=arc-20160816;
        b=LCKnEn31YkJLTqY7PlZ+gh99eAfZWvXCpmSkImyvysG9Tv4AC+wRCupe8l1an0u9CA
         otO2W/pK3ceF1bFAwdnWmSrPrYvyWWnVWRL7aVbTHCF2m9Vrx3szVMCpqcjM4hSPxy5J
         6UsjBZ+P7FOA+8JO01Ydu3UxHO5/nktjSSariz1NWlF8S36YSxdzc0fvSrCHKJ+0dR/F
         t/xE2wbBfGcNhHP587FSxy65WILs1UdvFun0ET3L+6/RHMXK1WNllWKSsCuTxotmYq8g
         bdmdXjiNh97NGO70AJySt8Awc0QuxPjIOUD1oUYj+MwrfzPjL5HGfIEToLKp+MK2lTnm
         Bv5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=cnclTT5q/9Or7RPJOyyBWzR51Gi82sOgnYxlNe09re0=;
        b=vG5jOY5ae2+yr2nCePWHqDk3RH6ZB+2hvYvDYhvU2WlIgiDJfpfyKYteAFz/IxQY9Y
         jV9dccrJ6sNZzkrHsSGyD6SqH84ySvsiBmgvOmIwX2/FFCfCy/NH/lx4HrqQ2G7C5siW
         UtvRj/Y2N+ziXcQ1jTk+QEQVlBWxIs27WaYnXpjqkmJEeL8SX40aLwT4ABjL5kKFN5YW
         vyGBltRr0hN2EtVLprljeQNXcbSkqqAfXjHCT+jwyC5VhdL1zcmoLcl/b6FPxnRVEkuL
         iR3oa61Kqh194g6tKVRpqHFxzT7QzK2fgLNgJsCvNx+NyyvwJZc9hG8e/WLl2/1krcsm
         T1tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jiQxPdF3;
       spf=pass (google.com: domain of srs0=fhsx=fu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FHSX=FU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cnclTT5q/9Or7RPJOyyBWzR51Gi82sOgnYxlNe09re0=;
        b=svc4rlk2m8aGcPlKO4UCV1+/R/NZEH6p2yZnCCbP0uNxaD4wIMobzAD25yt9UMkhue
         zXxC1wDC/2ckPSxyLzZvWLAKy/xe7fJtE2bXODpIGtGjbQnmgTfsVVLq9rtb5ZaUgIg+
         Ujrb1YJugClrPnJGuu8hd8oCZkmga6MvIPE29NW5qh4i0oTHxRoH7TN8ymyWQI66oLnY
         45n3V1n4Y8OzPjl3sZ5Riu3Urr8JpQOFUrHV8gJR2b5um1NrzOlU3HLzLWrNyQz6Gv+6
         YA8O439kkbwC9qmUnaoVs50X2oJPqKsO88Yhlv9rxcti0+23gNtAw+WfpU1vckwG6UVg
         9Jtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cnclTT5q/9Or7RPJOyyBWzR51Gi82sOgnYxlNe09re0=;
        b=m2KY32oiIgE6Y1VuKgAqWYXL9LILpyCT5bpZW9gG1sl1jMQoCUa15IOYMtvKoUKcim
         Cb1NkG//OwcvCcX0vndXKwWbkZuwynCp4btTBj4g0ChuijhLu4ewS04y50UyPAXo5dBv
         P2HdO6MgObSTsAEffyn73Y9N8GEB5cWGIsXwgo+ZcG3VBYDG79TSabnKCirIQrN+x7A3
         NiV7K0itlP+9YndBFsOAi1uPFasGMPRi/TfpKvvv2CjwMGIxrcHkaqObmFZh/bChRC4G
         m3uRoCHjEkAAxb/ty51nHoQaQfYCSc7oD8e7W5EKcRhWFjKl+E6H3mTKpD4YYyor7GxP
         21TA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531e4zjSsJUHj6CacduLTDzPgfEfFhvGaIRBJbTj4GLxsil8skkr
	omHz1RjuWtCKhnmVQd+qkNs=
X-Google-Smtp-Source: ABdhPJyKMbL1TsWfOLeDjA4PcN1Z1KbbQsCSFP9jDphh1VW0qwEERQqN7l4zV/nmLVRfgAV4tWDfGA==
X-Received: by 2002:a67:de97:: with SMTP id r23mr34650105vsk.44.1608154345111;
        Wed, 16 Dec 2020 13:32:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:382:: with SMTP id m2ls3167140vsq.8.gmail; Wed, 16
 Dec 2020 13:32:20 -0800 (PST)
X-Received: by 2002:a05:6102:227c:: with SMTP id v28mr3431541vsd.45.1608154340086;
        Wed, 16 Dec 2020 13:32:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608154340; cv=none;
        d=google.com; s=arc-20160816;
        b=cYRM0J1VJhW0RUhqZjXe1kGPy/Uyq/kQ6/COaW8htkZgEe2fb9MeyaPH+P8Z9nXIIk
         6X8/psgIF0V8dEZHtSQU/AhZgHAr4DeSNXgHGJRNrC7eOb09QBM4hPsHct/EiYmD0oCb
         TJjwFwwR52D+H9dg1zDrz2ZL8qimQonOexrNBJYRRZIH/cw49qdTk5KtbwhrGZfS2tGv
         PfcnVIR+IC3X4StaYAtEoppexjF1znr+YoFNwvSsKTISQ8IyLUwiCeTxLNZO16/3Kcwo
         R3y7tZJKMsXuErMz2REEylGpX4dxyE16RrEGkLf6u9WEjPqDz6CNvpJUhgKVh2x6W52W
         /CCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=3FwpIeysmLrTWEQ+PQVUGGjgOT6ViIz5/OW97/vuQJ4=;
        b=uOcjzYrOFtbCoyAcLPNPx0l66fUCYZAmKSoPNB6zpLlgonFsTJfK66EnFvWbh+hktU
         p+2L1YRYV/P1QpSIrnFqvpUFL0JQKS11aKtvRBhaMTufvaQSux2e+3G0nKGT9C13Wvgj
         sqt8GFlm6tqAdHoxwKymvK09fFRvnE5fNZm/nJ49RUeUX0dG9GB4x+kOrGvx1CuGAKe1
         Ve6MH0NkplYcEOGNshpucmQfVVwjcNPo5X3fS1iQl8tdBi+M4HkHgXoc7lIIH9h5K8z9
         VbRzO6xt8ma3gLQMJjjSeqwDVBMcMee9uvHximqH2gEYt5wYYbWR/4I8ljQ6oBYGqiMb
         jz2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jiQxPdF3;
       spf=pass (google.com: domain of srs0=fhsx=fu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FHSX=FU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e2si434359vkk.0.2020.12.16.13.32.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Dec 2020 13:32:20 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=fhsx=fu=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Wed, 16 Dec 2020 13:32:18 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>,
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
Message-ID: <20201216213218.GM2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
 <20201207194406.GK2657@paulmck-ThinkPad-P72>
 <20201208081129.GQ2414@hirez.programming.kicks-ass.net>
 <20201208150309.GP2657@paulmck-ThinkPad-P72>
 <873606tx1c.fsf@nanos.tec.linutronix.de>
 <20201216211931.GL2657@paulmck-ThinkPad-P72>
 <87czz9savm.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87czz9savm.fsf@nanos.tec.linutronix.de>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jiQxPdF3;       spf=pass
 (google.com: domain of srs0=fhsx=fu=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=FHSX=FU=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Wed, Dec 16, 2020 at 10:23:57PM +0100, Thomas Gleixner wrote:
> On Wed, Dec 16 2020 at 13:19, Paul E. McKenney wrote:
> > On Wed, Dec 16, 2020 at 01:27:43AM +0100, Thomas Gleixner wrote:
> >> So my intent was to document that this code does not care about anything
> >> else than what I'd consider to be plain compiler bugs.
> >> 
> >> My conclusion might be wrong as usual :)
> >
> > Given that there is no optimization potential, then the main reason to use
> > data_race() instead of *_ONCE() is to prevent KCSAN from considering the
> > accesses when looking for data races.  But that is mostly for debugging
> > accesses, in cases when these accesses are not really part of the
> > concurrent algorithm.
> >
> > So if I understand the situation correctly, I would be using *ONCE().
> 
> Could this be spelled out somewhere in Documentation/ please?

Good point!  I will put a patch together.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201216213218.GM2657%40paulmck-ThinkPad-P72.
