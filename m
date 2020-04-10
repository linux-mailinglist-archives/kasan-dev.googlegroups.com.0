Return-Path: <kasan-dev+bncBDN5FEVB5YIRB4FSYL2AKGQELTRP3XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id F3C781A4837
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 18:06:09 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id n26sf2669228iop.1
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 09:06:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586534768; cv=pass;
        d=google.com; s=arc-20160816;
        b=baj6t69fW8n8wAfwI6/GezynVTYjtdrcXSq+kXq++HcoZEbi2IhaIXiuQj6IHToM3h
         ToPNxp0RPFPugBkdZh17KRNYV3BlH/X81VnD7aHCrfTjoY/rV6zf/+NegBMOLDMU53xv
         ytNHB4YHvx5yA8Z72JtWsHvmPzMRSbHzsgRBQPVrj/f+7G5BquYbqjl/34jPAT/kTWEN
         K/M16Q2jDa0DtxbbYiHjvSxdVNZlPoQ2NdjN+amsjET8wUeadFZ7ALmIflQS6YDIQebM
         WKDzrJMMaeMEmAzRvezEQjXUrm2S9gtVZVJJx1oTuTak20TAi02mKqB1+Uz0UQiOy8//
         nAbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=O2hDfZByHBvAbmD0m+W2d9/yEzrsJKa2AILUM+482D8=;
        b=qckCNJw21WWTzcV7rMWpPc3PpEGDGf2XxP2SDrfB1CrzHHx9DRKwBkIcvyk3jIg9Ho
         V4FT6xjf2Gwq6eWaJ/07oHvEPsLfVRjFuGDShULXzOEc0mYbzyJ9b7nf7BHQa+/CfDA6
         LYekbvw8zK+BuufnpGqHHR60B/sY/EWtJ1c/zBZYUuE5YYB/A7mnkVvL9iV7/WnbS+tn
         ylVoAVYuXPTCXwxnfvYn4Tjas6blKOc5DM7EztI1brHCm2gcCsYuCyhHLpc40ItTebT3
         NOxzI3ngyUD6YoQZPl5VEtEsOU+Z5+DHUvPr8GvuhMwgfNZjPnRME4bSFiFkxS4/6kOL
         bIMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O2hDfZByHBvAbmD0m+W2d9/yEzrsJKa2AILUM+482D8=;
        b=n8Z0ZsUxkPpo27rD/OKkoJREYOypFzdA1IEq6N2tlDL2zlRkRcmDdmlpys9TKJ87eY
         8pGcqUteqd5IyERsMgf9thCIGz5mM7Lvy5utHgFlxxkbg/XuGDBIi7auMs1UPkab8/as
         XVuuZ/yM71737O2XlnYo5JgwfJr8ISvGNW3jJBW2ve5+B8O7cE+94epJCSxfD7SjE1Wr
         BLF4NzlJ8TDIBrQ3lmk37nWOoguv0LcVxR4KACp8+00DanVWdTpLT34/skeKq3TB7bG1
         KKlt+gVDTk5W9PPTkT56LSd7cN5vlRhfq/joU+f0lbJW0qKqQE8ba7V9IRowrGBh6+xe
         9tRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:date:from:to:cc
         :subject:message-id:references:mime-version:content-disposition
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O2hDfZByHBvAbmD0m+W2d9/yEzrsJKa2AILUM+482D8=;
        b=X9LG3/eLFmw7RdAb038vLWsLD64Pf8XIBhnBWJjcryD6of4f2A1EHmBJyfR63rHSRe
         OV226JRXfix+0ikjsHn1GGjL5zHw0GZoMAQHH0kACk2tLfbsxXuxmQah+Avs89UBZd7U
         kcZO+vlR47IOkfYNBRzjtgdPFOtsO3b3RIPOAJjbHlfp3ytTeke6NZIkQnhHK0dIGxw7
         wuIWRFEqIE/jYP+g5+xjosYxPCSrgH/hRSDp6Gg6/TwDAhzlvIdCIIkhj52lOZTT5G+M
         XiDeDycydUeREx5SEi0unjg9OGDn6QTJPApou4+lGIHRw2Bke7SnJTzRyoEkGJXi7/s+
         o75w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubqVhv3jxNqno6ktz7efDYz6WNRhU+05NQxEDgGJuSsuBZJ5w6t
	GVafAqWRcG5xbJkrMQ8J2tU=
X-Google-Smtp-Source: APiQypJaIdI3i6ONmxzxs9wVlx/SeBcZ2JU8xnN+Q2w4Yta1wGK9AubCnQwYCsLy/KzyRkw8mSxBkQ==
X-Received: by 2002:a6b:6c01:: with SMTP id a1mr4927233ioh.196.1586534768716;
        Fri, 10 Apr 2020 09:06:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:1803:: with SMTP id 3ls3804617ioy.0.gmail; Fri, 10 Apr
 2020 09:06:08 -0700 (PDT)
X-Received: by 2002:a6b:f808:: with SMTP id o8mr4883945ioh.139.1586534768339;
        Fri, 10 Apr 2020 09:06:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586534768; cv=none;
        d=google.com; s=arc-20160816;
        b=z56IXfNVMsG/llMHrwDH2Z05P6EgARpmOzvH8iKi41P2g+xMf3lU46lOWBen3emFhX
         Jgi1mjA/S9sFPY8VS8D/IBK9RfZGnDovnBSNsvydRTqda7Ie63O80iikV4lE6u0HI9mp
         44QK5pO4MiZBqlIkgzUEVVJKvH+6G5/Vh+kdpG4Y/a8WAJ2NjZ/G0BdMS4s/PP9oiUVa
         bSLgMvFRiuRywzZVMYA5nlA65jev5T4nlLzZgFcLZUPkOyhOtqFtaBhoVQR2Gzj2T86p
         7ulbSx5Rc6QtyHCdkOzX1QvuRhWLZLdQ+H7yxa7iLiC9k3MW673Fe8jECc2MahrkmyIW
         kvdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:ironport-sdr:ironport-sdr;
        bh=OLi0fLezI1uVuVZ272O/OvVc97aBKn/YPEeDH8/mF1I=;
        b=lqC+P9y4YcWZkmapl9fF9F/KxkqIuIsJaSLjCiOR2tBiiReLV4sEWoj+NFZzll/dmL
         wMykkWGuQ9TvreybuMvo9I7c+usHRlVvElOQp5qMVHifLyCH9wy09z2TVOPQmULJaubY
         ziIKfgairVunm7Xfxh3noKuP0lwijTO9/Sq7OOLqR+Ic99kIBpo9wRFB3h5b529j7S33
         JjICW3lSL0eNFZGYxCtmJ4RZDF2JYEYKHpyf4Mq/G/Q3ro5u89GGV6y2KXbxCxTVPg0i
         vO1Zdd8q+5tGbg5fl5snGqr+sKJZHJz8hq6gIwUVnAdsu9QtRtz4knD34FUA7dXKCMPO
         rdNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id m8si198754ili.2.2020.04.10.09.06.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Apr 2020 09:06:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
IronPort-SDR: XLXO3KIdEhF3cBVapY9nOuYP0QV9MwhTDfWy+wAFuqHSF/5RCJdUke7ttzG0os2H9NXiTrxjYm
 wDovvwkBnjUw==
X-Amp-Result: SKIPPED(no attachment in message)
X-Amp-File-Uploaded: False
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Apr 2020 09:06:06 -0700
IronPort-SDR: UXgOZj+U3clpDcQU5p6QTyNhf6cHt/ZwzHIo5iFymGE6zkF/k8LClS30Dk01YkWYhdSuoOBJwe
 osPP7YL93gZg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.72,367,1580803200"; 
   d="scan'208";a="252237989"
Received: from sjchrist-coffee.jf.intel.com (HELO linux.intel.com) ([10.54.74.202])
  by orsmga003.jf.intel.com with ESMTP; 10 Apr 2020 09:06:04 -0700
Date: Fri, 10 Apr 2020 09:06:04 -0700
From: Sean Christopherson <sean.j.christopherson@intel.com>
To: Qian Cai <cai@lca.pw>
Cc: Marco Elver <elver@google.com>, Paolo Bonzini <pbonzini@redhat.com>,
	"paul E. McKenney" <paulmck@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, kvm@vger.kernel.org
Subject: Re: KCSAN + KVM = host reset
Message-ID: <20200410160603.GA23354@linux.intel.com>
References: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
 <AC8A5393-B817-4868-AA85-B3019A1086F9@lca.pw>
 <CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg@mail.gmail.com>
 <B798749E-F2F0-4A14-AFE3-F386AB632AEB@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <B798749E-F2F0-4A14-AFE3-F386AB632AEB@lca.pw>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Original-Sender: sean.j.christopherson@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sean.j.christopherson@intel.com designates
 192.55.52.88 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Apr 10, 2020 at 11:50:10AM -0400, Qian Cai wrote:
> 
> This works,
> 
> --- a/arch/x86/kvm/svm/svm.c
> +++ b/arch/x86/kvm/svm/svm.c
> @@ -3278,7 +3278,7 @@ static void svm_cancel_injection(struct kvm_vcpu *vcpu)
>  
>  bool __svm_vcpu_run(unsigned long vmcb_pa, unsigned long *regs);
>  
> -static void svm_vcpu_run(struct kvm_vcpu *vcpu)
> +static __no_kcsan void svm_vcpu_run(struct kvm_vcpu *vcpu)
>  {
>         struct vcpu_svm *svm = to_svm(vcpu);
> 
> Does anyone has any idea why svm_vcpu_run() would be a problem for
> KCSAN_INTERRUPT_WATCHER=y?
> 
> I can only see there are a bunch of assembly code in __svm_vcpu_run() that
> might be related?

svm_vcpu_run() does all kinds of interrupt toggling, e.g. the sequence is:

  1. EFLAGS.IF == 0, from caller
  2. clgi()
  3. EFLAGS.IF <= 1
  4. __svm_vcpu_run(), i.e. enter guest
  5. EFLAGS == 0, from VM-Exit
  6. EFLAGS.IF <= 1
  7. stgi()

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200410160603.GA23354%40linux.intel.com.
