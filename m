Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBRPN3T2AKGQE3XGSDUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 01DF71AAD61
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 18:31:05 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id o103sf159504pjb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 09:31:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586968261; cv=pass;
        d=google.com; s=arc-20160816;
        b=R7JWFeM6IWU7kJRL+GK1XdmI3G1wc6dyxwvlkxkn83QJPMnFHSaXqjJ9cbBXN1GZ3u
         6R05T9uqQMdjPmiCzmLrrXFgdT///6Sc7ndLIQNoXILiwUu9tcbVY9X7HW5VZrnYP6fD
         +tbLIentbMBaCs+uSD+1KhgVT7aLW50eOAdE0bWBRZUHpkA5hShVterRDp0Qwhlo3t0T
         lLYhxCEkyvVIS4Dq2vE3UdPuMAmOL7hiq9qOdUVBP8nDQjvji34dpw+7g6Xg5JG4FR3b
         nYU50rukawIolEU+DQL7S60CBsGDFr6dF3QEE7mo2i16F0o5uIFEB4lCT6hJrKqfz+j/
         mg6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=nBJl3lxGZpvM7vJGmHVMaolIiuUxSFy1DoRLU+1Ms00=;
        b=lMT/FJJ5oVyyAUwyn+CFkHNbXEwIvE6hC7SF6pnOOvcLMx2oiG0UcXrtAZE78MMxmw
         r+jg+SM5NoYO/XdL3puyQD9N54qiAjQ9g9+ep9KQSq7HBr1l0x7Y3aX2JMY6631QL5h/
         HIoGqsR9D81grDdYwCCrevNP50dYeLyIwVoA8Rt+Ll1jv4uEnEQNAAhhUvpUAyne7zx3
         oF9M4EHK0caXs1d2A9d0qGxcgVsMCmY8bR+vnFAcS2KiX4dAMMk5fLnlYFFTud7sLHn+
         Zrn2g/r2Ce9euHyJqTw6SEy7b7bxyYv+WM64v0coewsnLanTXCDsCrBKrqgWOPnC0xOm
         nAmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=OIbcbV2E;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc:message-id
         :references:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nBJl3lxGZpvM7vJGmHVMaolIiuUxSFy1DoRLU+1Ms00=;
        b=PfiivtUSISbdHtENeMGaxcRQxxElIaKo9/mtpBfKpyOC04Buj71YJpZfBSffqJQswI
         ueILhTLyWGM3qB9X2D5PjNjyOabOoFxtD20sb747LSQX96bVxnZ9x3QvyJuyr2glUE9v
         uWCnhRElm2dAzI7lgjMwq+rQfsJiMN2eua7H1IquizTou+OOEC334MKyP9EzzrbdM3Cg
         Pz8sYVa+YKEm9oDzP0g3BwmaeErXDbL34Bu4nulUzwtOsuhl41MT75kEtJLn/hqDzUsK
         ttLDb96aAG7Y7ZsMQqODLnk8vJAZ0tG8x8/Lz266wqBN2UKRqIfASqI0TkLcXq7mQy3T
         iw+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:message-id:references:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nBJl3lxGZpvM7vJGmHVMaolIiuUxSFy1DoRLU+1Ms00=;
        b=idq7njg3Js5FWkdtPKQ3oKG4cfVn+BPd7QflrB0tFKtdec7+WFUJeycCFsRDkwGLCe
         IV2eafA0L0ZseLeNBCdZAqWAvwHGGZQ7Lxu5vRpE525GgcgEXjKZGU2A0NCLNKhb9vDd
         +bxenzz3RF7X37RZxx46LfnnsHCsjE7EdWq9kEhdbdV7oxCMKzW8wsDugNto9syPPE6o
         XdLEPWCnsRhZT5C6dve45zW26CsWYI0QQz3AuUERy4riDOu1KXBIl7OENFpmxnD3AyNd
         fN1cLbOGyOAsNx3Tco+kTNi8/TmAuy4IyVAlRYEqSHHi28UojAT73Ymjzq6AGVo0a1fc
         /Ocg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYv461c/bAUbaW7y1PjdawHZIoOMTah/9vaYB8BfAnEWSDhEvnU
	R+QmMnyFZqJM5fRff8XRb/o=
X-Google-Smtp-Source: APiQypLTpm0BKldIXcp8Hm2Ud9e0QO3OoRsZskv3vmdHl46kL6YjpdD8pQI7Ga7UzIAPENJpbLE3NQ==
X-Received: by 2002:a63:b447:: with SMTP id n7mr26596066pgu.278.1586968261300;
        Wed, 15 Apr 2020 09:31:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7682:: with SMTP id r124ls5527538pfc.11.gmail; Wed, 15
 Apr 2020 09:31:00 -0700 (PDT)
X-Received: by 2002:a65:64cb:: with SMTP id t11mr28324022pgv.62.1586968260921;
        Wed, 15 Apr 2020 09:31:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586968260; cv=none;
        d=google.com; s=arc-20160816;
        b=rfVO8zTGX+41pWlletZMBp4hW7SCYG4MRePpytRzqs67xo+SsrLczXWjN5YsBVInhr
         KVYP0bSF//cAqrb4KQWWOO3XhV+aU1vJLv+9FXkGepZojcPUBQw1mYQzDGjJI8VijeKo
         cP+ljoozVSwW0e5jR0yrruOkhqJnnWFQ+WFIYNMtGNxb4It0ZGGdAOXjS1w8IzIOJtcX
         FIgRR3GNgIWSvH/1GCxW5AE+R8GhIp3Wk9IWrXw1VhXV79POCJ57T98L4Q8Tfwi670SO
         VfqWB71lKku0uCS3qBKgujqeKv8dWuAezFRbjDxro+t4/ZcaIhl9xn+5EA1o2SaZRSA3
         j+Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=Pe2rnVHnSWvKL1ikgOoLe3CQ+A3ETgzCQ267TJC22Kk=;
        b=O7aMYCBzbFzfMbXV5BIrftUuKMnpl8m7sE8Oh+CraDJ/QB8XBZJUsZT5lkTgwm2L6x
         i5KbgcjyZCfz7RErB4pVNTOvwyNmGMrf+xwy90nlBcUWv9m9dRyt/JOB1dcLseHNgFym
         MXmgooKVsefqoK6OkH3CrkIsCY0l+wckJZotMSUXMi/NcIxYzoyBDXABgXRttdrnxIYU
         pwc/VedBqwiNmG01+x9Ik4SZQIcnZGXMfVLtV0lq51P6vu097ElEL10o3SdMbrk6mtso
         NzA6ryw8ql6PuHz6fJ7w/BirJUIZUrH1XbbYSXXcQRshgCxdbdyreDX2mDOPUHd2rhYR
         ejmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=OIbcbV2E;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id e6si958317plt.5.2020.04.15.09.31.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Apr 2020 09:31:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id f13so13622175qti.5
        for <kasan-dev@googlegroups.com>; Wed, 15 Apr 2020 09:31:00 -0700 (PDT)
X-Received: by 2002:ac8:4e2c:: with SMTP id d12mr2252732qtw.204.1586968259960;
        Wed, 15 Apr 2020 09:30:59 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id n64sm12808792qka.18.2020.04.15.09.30.58
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 09:30:59 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: [PATCH -next] kvm/svm: disable KCSAN for svm_vcpu_run()
From: Qian Cai <cai@lca.pw>
In-Reply-To: <f02ca9b9-f0a6-dfb5-1ca0-32a12d4f56fb@redhat.com>
Date: Wed, 15 Apr 2020 12:30:58 -0400
Cc: "paul E. McKenney" <paulmck@kernel.org>,
 Elver Marco <elver@google.com>,
 Sean Christopherson <sean.j.christopherson@intel.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 kvm@vger.kernel.org,
 linux-kernel@vger.kernel.org
Message-Id: <94BC9E64-A189-4475-9C75-240F732C078D@lca.pw>
References: <20200415153709.1559-1-cai@lca.pw>
 <f02ca9b9-f0a6-dfb5-1ca0-32a12d4f56fb@redhat.com>
To: Paolo Bonzini <pbonzini@redhat.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=OIbcbV2E;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as
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



> On Apr 15, 2020, at 11:57 AM, Paolo Bonzini <pbonzini@redhat.com> wrote:
> 
> On 15/04/20 17:37, Qian Cai wrote:
>> For some reasons, running a simple qemu-kvm command with KCSAN will
>> reset AMD hosts. It turns out svm_vcpu_run() could not be instrumented.
>> Disable it for now.
>> 
>> # /usr/libexec/qemu-kvm -name ubuntu-18.04-server-cloudimg -cpu host
>> 	-smp 2 -m 2G -hda ubuntu-18.04-server-cloudimg.qcow2
>> 
>> === console output ===
>> Kernel 5.6.0-next-20200408+ on an x86_64
>> 
>> hp-dl385g10-05 login:
>> 
>> <...host reset...>
>> 
>> HPE ProLiant System BIOS A40 v1.20 (03/09/2018)
>> (C) Copyright 1982-2018 Hewlett Packard Enterprise Development LP
>> Early system initialization, please wait...
>> 
>> Signed-off-by: Qian Cai <cai@lca.pw>
>> ---
>> arch/x86/kvm/svm/svm.c | 2 +-
>> 1 file changed, 1 insertion(+), 1 deletion(-)
>> 
>> diff --git a/arch/x86/kvm/svm/svm.c b/arch/x86/kvm/svm/svm.c
>> index 2be5bbae3a40..1fdb300e9337 100644
>> --- a/arch/x86/kvm/svm/svm.c
>> +++ b/arch/x86/kvm/svm/svm.c
>> @@ -3278,7 +3278,7 @@ static void svm_cancel_injection(struct kvm_vcpu *vcpu)
>> 
>> bool __svm_vcpu_run(unsigned long vmcb_pa, unsigned long *regs);
>> 
>> -static void svm_vcpu_run(struct kvm_vcpu *vcpu)
>> +static __no_kcsan void svm_vcpu_run(struct kvm_vcpu *vcpu)
>> {
>> 	struct vcpu_svm *svm = to_svm(vcpu);
>> 
>> 
> 
> I suppose you tested the patch to move cli/sti into the .S file.  Anyway:

Yes, tested that without any luck.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/94BC9E64-A189-4475-9C75-240F732C078D%40lca.pw.
