Return-Path: <kasan-dev+bncBCS4VDMYRUNBBU47S24AMGQE4NF7VGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A918995805
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 22:02:30 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6cb4180fab6sf127101436d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2024 13:02:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728417748; cv=pass;
        d=google.com; s=arc-20240605;
        b=KSbuEAUkV35xysYSA1G3hNMmINnD9J7YMcCk1jc3zTjvS6kFsUinzQA6W++aWseK+0
         wdPL9e6dDsLrwjgk5gOD2d01Owt/KUt9e/KweiIMQoUUA8byC77IL9KOP9ik6t0uXakG
         mbpndQT48RdIwgCmldTd95R0bd/7OoQrPgITuODRY6Yv3i3mBq1mCt2xlqLvdDFv5h0c
         QS1lcPxxqyn6Hl0ggqIUqTRcjb6VBmMyJLIHSHT8os5c/Vx7Z2+Q6BUfnid+X/206cK3
         Yj4czaUAkUbPWjc+TvyLknrdtJEBWAMlVXkgCCfdb6Dkimq2/Ec2QrfXRpX2L9NBFmow
         AXEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=21EUlW2RT6q6AcH2W1W/K5SJUm8Wnrl176m5mIvsxkg=;
        fh=3srhdGB4JUUzJ9s3N9J7DT0GOCr+3Wy6hyOh06G2LFc=;
        b=lqp4lV8Gd0i0I7MkdMkp4SV8AP8vwlWj/KTJeyrOatzrF4qIWaiIyHmBE+bUjBC8Tk
         /jtCi04EHVlFj7PoMcumDmJH0tzdZoYvvlGFCC+n8U0F9hgZpd7W6T9GVlVRTQHv7wsE
         CyBeizMzPkaBH0DqnWm5guAQkJLT/Tq5dnSm/KipMbevsQl/nimvldDnvBzWPpR/2EEi
         t0MNWMth8qjajSoOMMW5A+SqY9prnoEqFqzuMX6Rj2hLI9U6v2lsuKoy5mmn3Ywa242O
         ycpjOB+8m46+EaMYSeQVJ1zWGN2CAM8dqWV3wRcS8lu7Uh4AvWm+pTonP1OHCB8fTBes
         8KzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rN+E6v8u;
       spf=pass (google.com: domain of srs0=+lp8=re=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=+lp8=RE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728417748; x=1729022548; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=21EUlW2RT6q6AcH2W1W/K5SJUm8Wnrl176m5mIvsxkg=;
        b=VC1fzhDsvWr7YL7oJDPopI4+yomsrAwIaWntWMPIm/4V6R8QrAANJIp7GO+fNhEv77
         Vdl29YZOwvexRvKmXQA+BNGIbf3NawaHL4QzwE0liETyCr46LnBGOGBeFNi7zhD61cF6
         n3CZi02TU8yY04ibhI64KS5ybK5hbMnHqo52ng24HZrsMzwVCxsmGqG98ueAlvhT1E5k
         4GNFsCQ16G25zW+O8Ievcwtu+XnY+qVpPO1HHI+PMXdyxlgDj4OcB6Sc/HITU2kbmQw7
         BpLLvMFDhl/d7ARidLopm2R9TDXnyMVDk+bzpc3Z1rbs0qAZS8wX8kzTWyXKBznU0css
         9REg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728417748; x=1729022548;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=21EUlW2RT6q6AcH2W1W/K5SJUm8Wnrl176m5mIvsxkg=;
        b=mD+9iUQv91pSRS2ThBWebJOKouZg64noFV0KFgKFliIx1cetXHkIzKlKBbW7ZSfvit
         QVterDqIbB0L2qLJYIF0sIxSPCdly04gqNF2eJqz8HoIRp2XWlnDu/6g4cUkDQMRFIBX
         xElA4A3AqozQK934Kw12lRYfFGw1KiVowAfwwlCKqz+wEAAZWmfg0syUJat2mtVlOmx0
         WdtVFu5xxD2NrmABnhy4nOfG8twEJbu/zdH2z3pt+6OH5fvmE42dPjrpJaWDREDLLeiG
         pJR6aPb7qkEZObNVknbRzWlYXa5K+KchdM8fXy8zWyty5lKslp8h1M8uU9sp5dhW49xl
         JVVw==
X-Forwarded-Encrypted: i=2; AJvYcCUu/oGZDb/S3TTljFg0hCB9MY6u53hMQ1hMkSwwJbo+O5tLtx4J7mCXE7DLCjdbk7VRUWfOwQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywj64S7EkNT3ss0tFUd1pF8iu75/TQg77CGzcG+BV/CZc37Gp63
	+l2PT5+EmVr4WPZHfVB4mm87drU1BC999Tyq2KJhEIvZVPFB3Xvt
X-Google-Smtp-Source: AGHT+IHX/35bGC1GRMeKJ2WL0HLZ/+vYj7CICqvyRHZZFfutmfF10U/Dux4L1hk44FBtIPOUl/V9Eg==
X-Received: by 2002:a05:6214:4886:b0:6cb:5605:ffb2 with SMTP id 6a1803df08f44-6cbc942e22cmr2721976d6.24.1728417747590;
        Tue, 08 Oct 2024 13:02:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c6b:0:b0:6b7:8ba3:a39a with SMTP id 6a1803df08f44-6cb9014feecls25673856d6.1.-pod-prod-04-us;
 Tue, 08 Oct 2024 13:02:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUponhDpB9KC6HaagEgWe0P+YS0e1FexLrllanZSoS4l4i9VY4Fvl4QLRw7Yx5JWguGysnLvoTgpjc=@googlegroups.com
X-Received: by 2002:a05:6214:2dc5:b0:6cb:4b70:8ead with SMTP id 6a1803df08f44-6cbc955fb74mr3267356d6.37.1728417746707;
        Tue, 08 Oct 2024 13:02:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728417746; cv=none;
        d=google.com; s=arc-20240605;
        b=jpuJU3+HnbFvXAzjloMUTA72aV5IdkLNrwfzIou1ZeTfpq/fQvVgar2bYBKFqvfUco
         5TvlBa2FXAeviqISIb5wtSGoKs3vb5mQgrf/qP/HWiPUdgE0HgTGZYmoLloBpXTjoz4/
         xGTHmyCXp8uj2NEQx0GWXGafjKhlC8RaYuDcIGVtaEaVVeOtgTqIagM8ixLEDKz+DvX8
         M7XjEpAy1iGOvhs6tRlTtLHFcZBUaQAwhGZr7FObF84kX9KmiYYcQ085i+/4BZ1t+uWp
         rJfD55vw3X9cPjPH+Upk8pE2/j70jCPlKOJUqr5AiEIwC7q4p2suJ8Q8JNHLwJoCHoYa
         GZGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=V3xi2THeIJKWo6j4/LIB/KekZWWEmvsUBSIjXsdVk7I=;
        fh=b4rUQKQOOXPMgq1nkRYM+atCQEIVYCiymtW6U8DhPd0=;
        b=LFWWOnpW8DHCBjiutW0PP/J2h0wKSl5G987qD146T5abCTMPCwfkplDgXmx5uHssfV
         bTPlvd1i4U8DEUWmJjJbg7eHIL/iwjdNogM+hcgTOb2rFy+tauY4AZ5oYKANjaSYRs7C
         KZcgUEOeZQZWzNUptRuLGj2+F9fq9cy/wAJVwNUefZ+C3Xna7qxxoPatBnsPwP/EZFp9
         3JyjHKLmrmeQb3wiD4R9dmHe23BjocCYD1EYb8bRVrbUY/Ml4KyjCDIJfz411/nx/9TT
         uzQJQpuTUPGqMQHoUBFwC3m0napJmQlNRKtlhsOYEqVbzHTVbn6iyNtM2PkGl+RQN6nZ
         E5jQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rN+E6v8u;
       spf=pass (google.com: domain of srs0=+lp8=re=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=+lp8=RE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cbc1bc32c9si720856d6.1.2024.10.08.13.02.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Oct 2024 13:02:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=+lp8=re=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CAC925C5B89;
	Tue,  8 Oct 2024 20:02:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AAF43C4CEC7;
	Tue,  8 Oct 2024 20:02:25 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 56F9BCE0DD1; Tue,  8 Oct 2024 13:02:25 -0700 (PDT)
Date: Tue, 8 Oct 2024 13:02:25 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Julia Lawall <Julia.Lawall@inria.fr>, linux-block@vger.kernel.org,
	kernel-janitors@vger.kernel.org, bridge@lists.linux.dev,
	linux-trace-kernel@vger.kernel.org,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	kvm@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
	wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
	ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
	Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
	Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
	linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
	netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Message-ID: <acf7a96b-facb-469b-8079-edbec7770780@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
 <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
 <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz>
 <ZnVInAV8BXhgAjP_@pc636>
 <df0716ac-c995-498c-83ee-b8c25302f9ed@suse.cz>
 <b3d9710a-805e-4e37-8295-b5ec1133d15c@paulmck-laptop>
 <37807ec7-d521-4f01-bcfc-a32650d5de25@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <37807ec7-d521-4f01-bcfc-a32650d5de25@suse.cz>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rN+E6v8u;       spf=pass
 (google.com: domain of srs0=+lp8=re=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=+lp8=RE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Tue, Oct 08, 2024 at 06:41:12PM +0200, Vlastimil Babka wrote:
> On 7/24/24 15:53, Paul E. McKenney wrote:
> > On Mon, Jul 15, 2024 at 10:39:38PM +0200, Vlastimil Babka wrote:
> >> On 6/21/24 11:32 AM, Uladzislau Rezki wrote:
> >> > On Wed, Jun 19, 2024 at 11:28:13AM +0200, Vlastimil Babka wrote:
> >> > One question. Maybe it is already late but it is better to ask rather than not.
> >> > 
> >> > What do you think if we have a small discussion about it on the LPC 2024 as a
> >> > topic? It might be it is already late or a schedule is set by now. Or we fix
> >> > it by a conference time.
> >> > 
> >> > Just a thought.
> >> 
> >> Sorry for the late reply. The MM MC turned out to be so packed I didn't even
> >> propose a slab topic. We could discuss in hallway track or a BOF, but
> >> hopefully if the current direction taken by my RFC brings no unexpected
> >> surprise, and the necessary RCU barrier side is also feasible, this will be
> >> settled by time of plumbers.
> > 
> > That would be even better!
> > 
> > 							Thanx, Paul
> 
> Hah, so it was close but my hope was fulfilled in the end!

Nice, and thank you!!!

							Thanx, Paul

> commit bdf56c7580d267a123cc71ca0f2459c797b76fde
> Merge: efdfcd40ad5e ecc4d6af979b
> Author: Linus Torvalds <torvalds@linux-foundation.org>
> Date:   Wed Sep 18 08:53:53 2024 +0200
> 
>     Merge tag 'slab-for-6.12' of
> git://git.kernel.org/pub/scm/linux/kernel/git/vbabka/slab
> 
> So that was at 8:53 Vienna time, and Plumbers started at 10:00...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/acf7a96b-facb-469b-8079-edbec7770780%40paulmck-laptop.
