Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBM6U3T2AKGQE3EXF6LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B3A1AABFD
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 17:37:24 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id a16sf19980312ios.9
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 08:37:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586965043; cv=pass;
        d=google.com; s=arc-20160816;
        b=a0EhqMj3KGmvF3SSzuIYu608CVall8bov2/Alqzx6VzgWjSnVgz5NUflcL1q9pxJ0T
         mzXbiaPEdorG6gbh3atKG/5owz01ibUZjvBsEyO/cFw+0Cg+aotuHkWbSWYtZNm4iQgF
         tbSD/CTiUNJMEEmz+UOWLNTS+tAm4EDNYtYBK72xKAfwaiHMqFU12p2LbCZiZOZnc8Ui
         yUJcZzRg4Mf/gHPEvBZxqwdmkz7nnGyklmxlbfNCbncKs4UAS0GZ+GjQ6CVV4LuTO7TC
         Ek6GaPXfqidVeNrl1d+fIUVZ7ncGHaIYIe1J/xDSPFFdJcAIcJiIkUx4aLOzYBOUo8HE
         O+UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JfcsUVgtTD2gnd3xYb2suESCd6iE73pvz42NzsJshYo=;
        b=TsxRcw+5RpNxUcFTgKFg31LDXh7P3ScY89ugJyH/od+PZfF6sl2nr52sHGENSYhzya
         9EYIEEXL8jl3oTsHSFRiwLC1hX6wB+zzZOEWfMyuiMqjhHQ/NsUkKrANjk9Ki5L/Y55P
         KI/mX9hghJqpYjCfVEQjQasaMtmlvI11UBYIKDRb3Vcy03lT3/KAfVcI28u2/tRz3BeA
         bzjY5dPCHhu0Zbqog8wqoWRu2yAAxzSCnUqcRuuP7YAdXk1zi2WfWB6Od7DwVZXq6QC9
         Lhf1EES5P1WoDOJii6giiXGxDVfUcNmJwLYzv5D29HBruzAGv+KRfAgtB1REFO4I9Cj8
         dlEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=WRxp2lhf;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JfcsUVgtTD2gnd3xYb2suESCd6iE73pvz42NzsJshYo=;
        b=oRcP9i9dSa84Fyna/03iSE0JQNfpHXgtXXpi+rF5H0vcYKEq5R1+bm0crzNYYwZpse
         vhWwUqtixb22PYUZwo05/29HNA9MzcEVD7AD87xNeXFYoQWqtfKUwoPX2o6BzgOCf1BR
         ol38ehPagI6bOz0kpDVRnbqwKMFPix3uKMv6fgf/3ZiyS1UHp+CmwcxU6hk2xKSTEIoO
         Mi1ltl9oxIWOYKVr8PcWXVs+zh9naxp0BEahlIEyNEQZitfKrV3exbqVGJpspUHojsE4
         XMCVvaytQHsKRaLncFEEgp9gkv1SwR6kGq1wBFz8pB9CsgEgXs0kmkpK8a3MtchnzipE
         /Kxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JfcsUVgtTD2gnd3xYb2suESCd6iE73pvz42NzsJshYo=;
        b=sCF1CODeyLMkXyGdwICxW0EdGwZosCmt0UEts8CSbUk46+gq5Zb+oowUaNE8vnLZOA
         h1n5L9q5EJ4DGGGuchYMkiJJucWFW9Arz3Iq2+xfwKXhq8Jc5vJomLcNpbX35btyjZPJ
         K3qfg3UekUDHKvddE5tUPPCd7NMVGpBigvd59WndZy5GtFM8fylpK6z3bd9RDtBpDoIT
         nuuDl2/sU0RszwqztPxSe+1S9DDpahpJaEdpeN7Bmwt4sANyG0DkSkEdVu/XK1GnzgoF
         YuZ1HQbKemHqVb0rvFJpjYRPMmXkiLvl/Q7R/ObENLGeByCggkTj3Xeb3Bj5CeyeSuG2
         UuiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYB/nfxeh4g/U/f5fTonbsFX3+e7Hhn7CVF1sgGbNbZTa82+49h
	UGtVZHlJGX+dltlD7BGCRu4=
X-Google-Smtp-Source: APiQypLQRPzMe3oxREqWUsXaLbzY/RhPJe/QNd4lRkNjpyFwvCKJy96hH/dGk/24LYA2fznRM5nY+w==
X-Received: by 2002:a05:6e02:eb2:: with SMTP id u18mr6047471ilj.109.1586965043621;
        Wed, 15 Apr 2020 08:37:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:c381:: with SMTP id t123ls2204919iof.2.gmail; Wed, 15
 Apr 2020 08:37:23 -0700 (PDT)
X-Received: by 2002:a6b:91d4:: with SMTP id t203mr8850372iod.70.1586965043097;
        Wed, 15 Apr 2020 08:37:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586965043; cv=none;
        d=google.com; s=arc-20160816;
        b=J/bpZUlARCLJGFutUP4X9r6tZKB3lxhQEhJhbVKJlLzDug1kHIRJ/0isEzPFFAcETH
         9mzsUrOvmLPPKsA5aJnxxOXiVwG1E+BJ0/ggqm0wJ2AsPdUroUUgh3XddEkfMvNYxAn9
         e6Wd4ICKHGVy6QQrUnPF9INJAoIhJQWgaCHJKAxCvKbEEF35JfLdflXuqiMfNGYv7RZc
         SwFZ4fjh62jIa9cnxus+323DNiKLXdKCJMB2g0VEku3ZamImDbq+gG2xS7APWhbtbYRn
         rbvVjRuxW5qFQOgs6gpWjIvXD9IfAh/O88iqbHGcjUPGJuYQjeixPQWksEO19ojriT/f
         2A/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EeFIVTegln/F+8Ij5JttngNbXaEaGERsEIMec13qZzg=;
        b=IFTwPfUK0CAAt37Z96PIeAHfrpIHY6DpZ3dt3fLS2X3pnGCpEAl/mHC+qs4Y2Sozrl
         j7KHRh6JzE8ZJj1VS2XYrxBLC1V8t2Po5uQk8uFLsbTYxhlSPNxvb1tOJAjABMFI1ufG
         8pv5uvq3OR1fo0jt5sbuH5iIV1sLwohcOXQ5W92Mur1h8SOcWwrmRzg5wH2A8mlIqd4Y
         KfFdjEpa1YqEPvfjNwLeQ6xiQ7yhPDdRHc1VR8hE2y3uXiT1ELg3G12t8m4hug49n7E0
         T4k2I9SroeQTLF43xweLATVNmmuqWuQNRa4WzR7NsnDBriBZ1PUtN+fP5//fdHdLIvJz
         IL8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=WRxp2lhf;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id p5si221946ilm.1.2020.04.15.08.37.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Apr 2020 08:37:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id l25so17670125qkk.3
        for <kasan-dev@googlegroups.com>; Wed, 15 Apr 2020 08:37:23 -0700 (PDT)
X-Received: by 2002:a37:9dd6:: with SMTP id g205mr8286950qke.9.1586965042621;
        Wed, 15 Apr 2020 08:37:22 -0700 (PDT)
Received: from ovpn-113-148.phx2.redhat.com (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id i20sm12549999qkl.135.2020.04.15.08.37.21
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 08:37:21 -0700 (PDT)
From: Qian Cai <cai@lca.pw>
To: paulmck@kernel.org,
	pbonzini@redhat.com
Cc: elver@google.com,
	sean.j.christopherson@intel.com,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>
Subject: [PATCH -next] kvm/svm: disable KCSAN for svm_vcpu_run()
Date: Wed, 15 Apr 2020 11:37:09 -0400
Message-Id: <20200415153709.1559-1-cai@lca.pw>
X-Mailer: git-send-email 2.21.0 (Apple Git-122.2)
MIME-Version: 1.0
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=WRxp2lhf;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::72d as
 permitted sender) smtp.mailfrom=cai@lca.pw
Content-Type: text/plain; charset="UTF-8"
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

For some reasons, running a simple qemu-kvm command with KCSAN will
reset AMD hosts. It turns out svm_vcpu_run() could not be instrumented.
Disable it for now.

 # /usr/libexec/qemu-kvm -name ubuntu-18.04-server-cloudimg -cpu host
	-smp 2 -m 2G -hda ubuntu-18.04-server-cloudimg.qcow2

=== console output ===
Kernel 5.6.0-next-20200408+ on an x86_64

hp-dl385g10-05 login:

<...host reset...>

HPE ProLiant System BIOS A40 v1.20 (03/09/2018)
(C) Copyright 1982-2018 Hewlett Packard Enterprise Development LP
Early system initialization, please wait...

Signed-off-by: Qian Cai <cai@lca.pw>
---
 arch/x86/kvm/svm/svm.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/x86/kvm/svm/svm.c b/arch/x86/kvm/svm/svm.c
index 2be5bbae3a40..1fdb300e9337 100644
--- a/arch/x86/kvm/svm/svm.c
+++ b/arch/x86/kvm/svm/svm.c
@@ -3278,7 +3278,7 @@ static void svm_cancel_injection(struct kvm_vcpu *vcpu)
 
 bool __svm_vcpu_run(unsigned long vmcb_pa, unsigned long *regs);
 
-static void svm_vcpu_run(struct kvm_vcpu *vcpu)
+static __no_kcsan void svm_vcpu_run(struct kvm_vcpu *vcpu)
 {
 	struct vcpu_svm *svm = to_svm(vcpu);
 
-- 
2.21.0 (Apple Git-122.2)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415153709.1559-1-cai%40lca.pw.
