Return-Path: <kasan-dev+bncBAABBT4YS36QKGQEXOGTFQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 898FB2A9B2D
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 18:48:00 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id x85sf1207639qka.14
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 09:48:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604684879; cv=pass;
        d=google.com; s=arc-20160816;
        b=mra2CMzAttK5wUH8tTn4j2ITr+stZcNTnAtnPh09JRN9sgeWf5oo0M2U/shDQV/UNz
         VJhaJ+D7ee4fP+7Yol/Uw5uGB3WwWRQ/YpTZfxae+NSkzLyS8EGxuMNU/EwpQQ+SVRue
         /35iG/1ABZAiisjP8iJPJEaOtT3Bsd4gFUdCaj5w4sb9zRc60zwahj3lKr6+PGI55w4V
         TOb29aUb3tyWmTz3+xZOaNPhm6Htt35lRR2Jx34U0K9U40dJXIfNlftkifi4spkIYV09
         vPbQIjINaABgHgZanHNC2j1QpND2q/s40JrJbY1fe5KY6zae6rNs6ziE5FiCHTv8mgY0
         nC6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=+YXV1sCeJJpfDxGEeZ4CTdgaRJPijdtblUkeqNoFKII=;
        b=0Kp0W7eUepqzZxLDhditt6laAek2Dw1XhLYLhFgEFBJiYqpkf1wN2stJdm13/VD2pz
         n1e+5bITDzhtcPEOaEtwftW9ZMeI48P4N9G1/aecZNB6+Llmwh1y7epppkJFDqFw/chb
         fkDm4C3FtXMsSLwSZj+69L9XP9oebDVpOOQABlPWVulQ0imqaRTI4ckjL+UVU7KaRueo
         75i17kWj26sYiC9I2x6SQaFQuCe4bpWUDcbr2WKan+wKc90CTjHICXgDf/tT9jNykMPC
         N7wJlviphuplXPDSrlyOqxTCtIc+pkhgAZsn/Q0h9OZ7yDYioYPbss0nqFzY+M4e0vAa
         490A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ESC06jg3;
       spf=pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+YXV1sCeJJpfDxGEeZ4CTdgaRJPijdtblUkeqNoFKII=;
        b=mUP0hkG/tpDbVQqvXdoBU88/BjCM7nFcW5FPINy70813g/uL3EObt/SMSE2JYqJcYk
         cse8IwAzlMjyk6lSTjDEMZ6jXPMSNz4oYKB+1O5c5Oy+dt+iQHp23Xd04a8ep7Eg/CCw
         Qgr+e2+yWVM0bdJ1kjKEghZDst0RgKqgY/F6OReJXlqYvrqlMNiHzV7K9LDtR2dlMUZq
         xfStxvnyjRzUM8UR7NQMfyogKsWv97BvOPEwoSNXFiz4X1+fw7Irtx5wKUSkCBsKNJWT
         5eGfBH1msu1NzIursa49JkV5nbVto439lt5DGYQ9lf9hoMqu3PmRVwNW6nlyt77RuisN
         MJIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+YXV1sCeJJpfDxGEeZ4CTdgaRJPijdtblUkeqNoFKII=;
        b=ft1lyDqAatjN1DnyQoFPLt4hNAKq1VSKLvcbRO0pH/aWtt2EvJcdGZKSE6atlGR3oJ
         5ayC1diJd556LTyzsw6PdcRHaUjpZot5bUUe1M0ehVG5uzCS1oPM6g4zdJyrmVcT086w
         evYVFtdVqdbPoMAWIl52JLZA06tlvX5eP0j3JmI3j7h7jsEEoKtBYuasrWfQn3BUYRYc
         HxNd4RDv1k+6H6F8/4706+LuiZ0l2fNSP+GTqK/7xqzmU7OKqTg5+MlNt13sLU0TbUbL
         S8OEiL7seGXjAlNA5bNAc0BA+vuW/qN6aq6dv2GJz0k0IpbQS2mVmYWR8f9MnTbX8NZa
         PRzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533yBGsUv8um+apoCayTg07ojQogxyER9FEDuygMO6r96cSWNDl2
	24PZ0aD3vHLChCXj5H7VIzM=
X-Google-Smtp-Source: ABdhPJwUMe1j73kIo2FYEibjs3yyEkFffSdJ+U7DecVpvlqPPYUNmxbjuIraYx7vyhlHxAjz3NHC2A==
X-Received: by 2002:a0c:d40c:: with SMTP id t12mr2669981qvh.37.1604684879185;
        Fri, 06 Nov 2020 09:47:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a8c5:: with SMTP id h5ls453072qvc.0.gmail; Fri, 06 Nov
 2020 09:47:58 -0800 (PST)
X-Received: by 2002:a0c:ef02:: with SMTP id t2mr2700298qvr.7.1604684878627;
        Fri, 06 Nov 2020 09:47:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604684878; cv=none;
        d=google.com; s=arc-20160816;
        b=MgzVK0VKKggdPU14T5gygvCy6dQuQFHqpP8onvcXnqw2embcuLZI9n4Gy78HSAWoST
         nl4npxwB73jW+0QvDi8fWjh9VjcQmXT6C6QdcRdPD32nTHT3e6mhJgfoOgWq8eA81W81
         r4MH6+4yYcMKaaHjS5Fv8rz+S8FNVUYaviuyh6bvYe1MsxKuiaEFLXPzxiKg92rQy79j
         ZMbS/RSg3Hi8JcqFeMe0PDCFyn8NnxXWxOgrkeFMrrNEG/2R9q9VSzTiVfxc2Gxm+LmO
         VnlMhmkRN/LBvsIKmpdb4r6FDCZQfiay3I+CBeR1wAWiGE20jp+FxbnHqlhbhoAtstdt
         5nyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=AWcNkduOGPPnJV7IHwhhOIXyJYb1t46TOUHxdX4r3rI=;
        b=dJVAzi7CN5zBLM/0/DfXN1esmLNEOsFC1UbCWOOZC7l3jI5dYOn7RPeU133HP3OfcZ
         kPkgtY1uIZNdb8KaeOS8xThrA14SpNPdrhRo8fysGtNAiqfqljjb4mcSzYxmEEFPIa55
         zDNUQyV1OjM9Orp6Aa6nLAm8cGphCUGU+VroZByRMb0Lp5zN9Vt6DoqThIWkMe4/TkGJ
         z1rw2YE7B3vaSb/QCQWkM4h0hZVse4pnm2Nwu7MkqAjL18DGn1UeLc9vsX77yQVajfIF
         FlpHDReu4CwMEd19ecHO2EW8N19IsilHAWsAzUGf6ilan/Du1sCSbsem7a0a0EdWyYW9
         KsnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ESC06jg3;
       spf=pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n4si101341qkg.2.2020.11.06.09.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 06 Nov 2020 09:47:58 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 61CFC217A0;
	Fri,  6 Nov 2020 17:47:57 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id E286E352097B; Fri,  6 Nov 2020 09:47:56 -0800 (PST)
Date: Fri, 6 Nov 2020 09:47:56 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KCSAN build warnings
Message-ID: <20201106174756.GA11571@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201106041046.GT3249@paulmck-ThinkPad-P72>
 <CANpmjNPaKNstOiXDu7OGfT4-CwvYLACJtbef8L0f18qn1P4e8g@mail.gmail.com>
 <20201106144539.GV3249@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201106144539.GV3249@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ESC06jg3;       spf=pass
 (google.com: domain of srs0=8wku=em=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=8wkU=EM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Nov 06, 2020 at 06:45:39AM -0800, Paul E. McKenney wrote:
> On Fri, Nov 06, 2020 at 09:23:43AM +0100, Marco Elver wrote:
> > On Fri, 6 Nov 2020 at 05:10, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > Hello!
> > >
> > > Some interesting code is being added to RCU, so I fired up KCSAN.
> > > Although KCSAN still seems to work, but I got the following build
> > > warnings.  Should I ignore these, or is this a sign that I need to
> > > upgrade from clang 11.0.0?
> > >
> > >                                                         Thanx, Paul
> > >
> > > ------------------------------------------------------------------------
> > >
> > > arch/x86/ia32/ia32_signal.o: warning: objtool: ia32_setup_rt_frame()+0x140: call to memset() with UACCESS enabled
> > > drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_prefault_relocations()+0x104: stack state mismatch: cfa1=7+56 cfa2=-1+0
> > > drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_copy_relocations()+0x309: stack state mismatch: cfa1=7+120 cfa2=-1+0
> > 
> > Interesting, I've not seen these before and they don't look directly
> > KCSAN related. Although it appears that due to the instrumentation the
> > compiler decided to uninline a memset(), and the other 2 are new to
> > me.
> > 
> > It might be wise to upgrade to a newer clang. If you haven't since
> > your first clang build, you might still be on a clang 11 pre-release.
> > Since then clang 11 was released (on 12 Oct), which would be my first
> > try: https://releases.llvm.org/download.html#11.0.0 -- they offer
> > prebuilt binaris just in case.
> > 
> > Otherwise, what's the branch + config this is on? I can try to debug.
> 
> You called it -- yes, I am still using the old clang.  I will try
> out the new one, thank you!

Huh.  I have an x86_64 system running CentOS 7, and I see PowerPC
binaries on that page for that OS level, but not x86_64 binaries.
Am I blind this morning?

If I am not blind, what is my best way forward?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106174756.GA11571%40paulmck-ThinkPad-P72.
