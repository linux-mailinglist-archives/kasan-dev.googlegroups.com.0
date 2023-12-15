Return-Path: <kasan-dev+bncBAABBW4O6CVQMGQEBW75NCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id EC73B814312
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Dec 2023 08:59:25 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-55220f9410esf1699243a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 23:59:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702627165; cv=pass;
        d=google.com; s=arc-20160816;
        b=S36iwVrAM7YpY5iYP+GOqGWPnR3PT+tfwx3r+HksC/wcksE7ByyynukqDgtDHuWd38
         P9lb6Kf9SbpTj18wUoOKm3PwzSd1e/qE4HgdvYnpm4buz/LfWeCkzEwRjHVVRlK1hq+A
         hOcSnqtbGijw5DBAoRqA1AxL7fRcXB9ua/Xtkw9pTFZydOj1ukVugtTRLO3BajIoyK6C
         YvgnefZ5RXSj2KwcberXQAO7Hy9CB+K7qHakE6zup27gYVQIh9Bflp7BS3xXVHMLLAvK
         nOSUpawGYAl3XPqLhErU2BvYrfxDiuXU2Qkl48fVsbip4p4nEG7fAqV5Qo/fkH9lZK4D
         d7PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZzA/x+rQlTq6yZ1N3Z/A6uop8S2I7X8X3Qqh9XWkIAk=;
        fh=OuvxDo77Do6uBLFUZ1NY/JZZXNK7wZvnurp88/rj1a0=;
        b=p4D4o33i00IlsSLS4dp1WjF99cXKofl/sdz8cNU2ZjX/rkGOZmMmhEa10Mwfp2Ycr9
         V18qYbu1nzCYq5dKsEMI7x6d+dSA8OtkMF/9iNMYf3pIjJ4Qya34wdCVUt86NDfxWj35
         +qJEFwMaSCsaywAyIwLTOztGsW6IsxK/F0Ci7/kIO7olJtEoa9d9u00qP3oKwWdtR1f4
         0iWnCHSHHmFWtAxCTMifky3dnOYqT0r6Bt/SGUxUZFOAVi/YROlt3sUO9abvQ4ydFA+H
         Qn7DblfWpYsJV0+wPmHZtcd6BTURhEWLJxrQHcBFkUZsD0Lp1NeMvKS6DGesls2U68hr
         XyRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VWGGsr9g;
       spf=pass (google.com: domain of naveen@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=naveen@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702627165; x=1703231965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZzA/x+rQlTq6yZ1N3Z/A6uop8S2I7X8X3Qqh9XWkIAk=;
        b=fV+0Comjknjo908okvvVnxV/kstTwPY5y3HXfTl/8L5WHbLhCegAavYBboLbs65LDb
         ZKkxRRcvj7UGKUgB5ExPzNY4aUP62OlaMAVNj5wZo8ptuGUKxtMxMSd83lUFeoUZAixe
         4qDdG3g4iAD3U9k1rqC81waIKU/hX2lUy9FKmDTv9w0ykwx4dZGLzdIsZNQowM8xYmwb
         fxvKfwkNwVmy+04sXzAIUXPdpYLGsLdMNKHbOhdklZWlzzmOKs2aAVyjBm2y6OBpHrdV
         a5zjxb4qTOSZ4xosIghvtOc0+xP+yxEgU90qOIFrB1BAhNiz4oh0PizAorSB7HvIiS8q
         MUOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702627165; x=1703231965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZzA/x+rQlTq6yZ1N3Z/A6uop8S2I7X8X3Qqh9XWkIAk=;
        b=Ulin967BVskk961FSLa/px+nNk/HMuVKuNvrw3W6YCHM0cLA/Cx7Vb28GIcoma2WvJ
         Ey92r72WzwwP61kAScTRvth6+KgAxI8wR3x83JLBJCmkBxfZYuWaGwI/6o6d6NVvmVXa
         MeOGFoR41QPcJOkZWVc5nPHUPUH+lRwaVIVffXtSHtjTOB86ffMWr/71N6OXWDF8HOpg
         7q9BBXueP8NUPLYLGyn0ylPD8B3NN4GgoO8pZzgAjyrEZxhH0llpOFQvWbAja26yqiz7
         TEKyC6Cy65jL9P+YAp5NjGy1gV/8bLBOQJTTZPWuAYK6vNToa7FxmLs8tzE65gnFRPdJ
         DtmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwUewGR5iygmh+gkhS9n4GzKhF1rEV51be0wnd/B+LNVGmyr4HN
	/E8Vt7oVvrltknKSM4R0F5E=
X-Google-Smtp-Source: AGHT+IHrlN3oFQkuMx7BDIiAtIEw15SAfuo2/lWsh2BT626X5CJfh3CJ7ysEfXgtl5pESiWxUuUsNQ==
X-Received: by 2002:aa7:dd0b:0:b0:552:2981:bb6e with SMTP id i11-20020aa7dd0b000000b005522981bb6emr3905866edv.9.1702627163955;
        Thu, 14 Dec 2023 23:59:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5106:b0:551:c719:67b5 with SMTP id
 m6-20020a056402510600b00551c71967b5ls114294edd.0.-pod-prod-00-eu; Thu, 14 Dec
 2023 23:59:22 -0800 (PST)
X-Received: by 2002:aa7:cd15:0:b0:552:9412:44f0 with SMTP id b21-20020aa7cd15000000b00552941244f0mr1236452edw.14.1702627162217;
        Thu, 14 Dec 2023 23:59:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702627162; cv=none;
        d=google.com; s=arc-20160816;
        b=A0QoXGaigPSZC3YcocF/qibGqQo5SkRWbMgm/AUC3ZJqmlVzYEQE0BLP/LD0gmDXXN
         ovk4jjFKCsmWKhKH/e+fGrU7/9cKzBN93cWviboQ0f+AX5iUPAif0ynbwlP32ZS/yWNz
         sfu/zI9RTBRlgiLTAmRW2J5N/Hmvk68vN91QPSMr/qza6rJgdqgI8SSAdiZ8K0Pdv7Fv
         uQ/BmcpPfGc+zLiuGuMtmQ9okz4JhVleFelOqxedEGXqnxMDN6Z5BAXmrXExmt5Lw0Wt
         SnYEJaRR3HxSFeXFY9y3kZ6QC/uiORz9Zt+apuv6Bx9bAu2XWZsV8XcL48GtAioOCJuh
         aK2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kS+KsCt9BfbC8mqWlYiyak+nsTKsd1LEGVX3pkRr5p8=;
        fh=OuvxDo77Do6uBLFUZ1NY/JZZXNK7wZvnurp88/rj1a0=;
        b=ak0apMUMl50nmRBzA38bso+6umoauaG257fRj+ek0OKrN26tYazlph+9ewsaJt15/9
         xpbpI7F7Ip3CMhO/lZWPmEF9S0bPRMKA20s5Om7VVN8lSnIxkskncR1EjIhzzTkB4w2u
         G0dmol5+OXARxgLx1N1NbHdVo4gsnqGhn3NX7uzp4aDtb2rANCILpWfAdfrcvIOp38i1
         ZuGXutK+dIAyzEO+dlQri3fve1vVMNECAmfACoTwcGCrfim8+ki6EJsOFoxmM/73Vxmh
         pkMcnbfonk2U/dvJ++nvlfzylJrBtpfROgp7l+CNTEJLXoez2VwyelsjLH9UgohjsXrc
         kr1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VWGGsr9g;
       spf=pass (google.com: domain of naveen@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=naveen@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id p22-20020aa7d316000000b0055259d9e91dsi178726edq.4.2023.12.14.23.59.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Dec 2023 23:59:22 -0800 (PST)
Received-SPF: pass (google.com: domain of naveen@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id E93FFB8215D;
	Fri, 15 Dec 2023 07:59:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7BE0AC433C7;
	Fri, 15 Dec 2023 07:59:20 +0000 (UTC)
Date: Fri, 15 Dec 2023 13:21:44 +0530
From: Naveen N Rao <naveen@kernel.org>
To: Nicholas Miehlbradt <nicholas@linux.ibm.com>
Cc: glider@google.com, elver@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, mpe@ellerman.id.au, npiggin@gmail.com, 
	christophe.leroy@csgroup.eu, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	iii@linux.ibm.com, linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 07/13] powerpc/kprobes: Unpoison instruction in kprobe
 struct
Message-ID: <xn274hbvxsfwii6lwis72ntnphiixvcob6hkopn5fygutht3qe@j4sau5ejaxwj>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-8-nicholas@linux.ibm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231214055539.9420-8-nicholas@linux.ibm.com>
X-Original-Sender: naveen@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VWGGsr9g;       spf=pass
 (google.com: domain of naveen@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=naveen@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Thu, Dec 14, 2023 at 05:55:33AM +0000, Nicholas Miehlbradt wrote:
> KMSAN does not unpoison the ainsn field of a kprobe struct correctly.
> Manually unpoison it to prevent false positives.
> 
> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
> ---
>  arch/powerpc/kernel/kprobes.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/arch/powerpc/kernel/kprobes.c b/arch/powerpc/kernel/kprobes.c
> index b20ee72e873a..1cbec54f2b6a 100644
> --- a/arch/powerpc/kernel/kprobes.c
> +++ b/arch/powerpc/kernel/kprobes.c
> @@ -27,6 +27,7 @@
>  #include <asm/sections.h>
>  #include <asm/inst.h>
>  #include <linux/uaccess.h>
> +#include <linux/kmsan-checks.h>
>  
>  DEFINE_PER_CPU(struct kprobe *, current_kprobe) = NULL;
>  DEFINE_PER_CPU(struct kprobe_ctlblk, kprobe_ctlblk);
> @@ -179,6 +180,7 @@ int arch_prepare_kprobe(struct kprobe *p)
>  
>  	if (!ret) {
>  		patch_instruction(p->ainsn.insn, insn);
> +		kmsan_unpoison_memory(p->ainsn.insn, sizeof(kprobe_opcode_t));

kprobe_opcode_t is u32, but we could be probing a prefixed instruction.  
You can pass the instruction length through ppc_inst_len(insn).


- Naveen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/xn274hbvxsfwii6lwis72ntnphiixvcob6hkopn5fygutht3qe%40j4sau5ejaxwj.
