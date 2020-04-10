Return-Path: <kasan-dev+bncBCFYN6ELYIORBK5SYL2AKGQE2FE4QVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D62721A4834
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 18:05:00 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id 193sf1128608vkx.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 09:05:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586534700; cv=pass;
        d=google.com; s=arc-20160816;
        b=XVNgGC3MbeMjwNevr9yW+o8yv64Ichv0u/EK8aY3HVukKDuOzasat6BLm/ZeeF/Qc9
         WRxopYUbUdGON5uvluxHGNbS4Ht9tYDFv5Z+RHNdQXb3ywkkn5pxmgWiL4gm63bi5/52
         8lUQ72C+kRC2mHIBoVN0BktpeKSYyRHim1DOnEoh27txh5RmJPNG0Bk3NwsGfLI18A2y
         6eO7mZGHcHdLKkWCV5ax4OpKaBOW46GKuvS83AHaLI8z69OCJSi3MoT+l793RpsVVx7z
         jfyzrgZhDvrT7SQr2bE65iWd35XBAbYKmclfTM60nHswo/5cZu94Yu0YM8UWFbcj1zr0
         azZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=BC2XCIYBidKUsqnZaLTkiSwi+2n9sVxQtRrvleBKXgg=;
        b=v8d2wHQ2RZoKVG4YpeeABomiVka2oDTr2bAgc0uUQUTFi86RTQ0+BYwbHX7B2NZuph
         gSB0htN01VbVsnBOzZEd8kfKjF3jgf9PsdTzBDHqVa+Fy5W5OJ8Gmpz3q+/3fQkC/Vc4
         F0g5fXS5dhjhuRNDgnoPrAN0s3gZ+FOM9nT+gygRtv0Oeg9LBywmYAGVKSz0pzdAHrSp
         uF6mdKuKFau5/aDeTWNo1IDfgvlBAY6OZfhS4JiRKYFi4AOfnDawApi1YVYX8mwoIxgv
         kCLTedvvYaX5+zPN3V9A81H4jYu71KXox7w93CzbY6p1kV+fPU1f7s1nokmElKld4Iaz
         6nBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Kcjra8yw;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BC2XCIYBidKUsqnZaLTkiSwi+2n9sVxQtRrvleBKXgg=;
        b=eWEtCldPwEpBKfpQTfY6W7k4AM9W9LobOU5OY9xN+W8oVO8HWFqm6SkMy/U6oOU8Fk
         O9JtMOLqDr7r1Ams78kEczEsan+fH79lOBBseYW9iGLaDINYvuU15yEp3J4GiiyWVxcL
         HKgkusOI+uiBvYpM39aL/7YORpM3vg/5x3ydyHCVhJBG/7mPSUWRwT0G6SyPpk/8c/FM
         oe/ReEIz3A9l9QzYHRUboVz2pVeEs0rmrW2jB4rDYU8QFcgK7MFpMWDVWOSduTudqvqq
         vEy3Gfl3BqdMcZE18NnE6FQt4DljusreWhOtioGoLPsL2LxkzFW/AyHotxVIaM12iqEA
         Y1jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BC2XCIYBidKUsqnZaLTkiSwi+2n9sVxQtRrvleBKXgg=;
        b=A1CibRpsNWAqScTVZhl4Kw6+1LwHGESDmYQs2QBGKcohDVb8BIvyvQv4VRP5W7LPc6
         tNnjgVppHSLT26ywYpplqAJox3TVtexG9UclVn6fGe54DAho6S37K7fto8EsfaKWeWln
         ET4XVhljs2mDD4oayouwqd8JJXJpZQWSB2o1xCjgcAedvFQ4yj8QbVbvgpiXn5Jz/ACK
         0JqBwpVZ8vXyL9dwFUOBVDAq4GJI8XZMiB2du4oMu1y3ABYOd5Xd2d65sLyUt4cc1+K5
         67cJ0ofn9FOWLSylPkQ7YABt9PC8Qz0oh/G89TxHu7GLs34mKWVkM0+Ow40IXrrjDgW4
         P3XQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZvu9xv3u1mOq50PWoiLroavTsd70L3Uwt4acXrHQVVdWs4ySl0
	97Pq/rSbsnaJuCPnjAP4fLg=
X-Google-Smtp-Source: APiQypJVD7tv9Xd2Xdducmid3urXExuHvfw87GOxD9suH9sNFqMXoh/LL5kuz7lffpYxK5lOa5Hpbw==
X-Received: by 2002:ab0:2b05:: with SMTP id e5mr3626432uar.24.1586534699835;
        Fri, 10 Apr 2020 09:04:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2f07:: with SMTP id v7ls1512108vsv.3.gmail; Fri, 10 Apr
 2020 09:04:59 -0700 (PDT)
X-Received: by 2002:a05:6102:2414:: with SMTP id j20mr4426825vsi.206.1586534699288;
        Fri, 10 Apr 2020 09:04:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586534699; cv=none;
        d=google.com; s=arc-20160816;
        b=Znr7ueOHTI/Rf+ErcGzxSPuRCOND5UScEOFN6MnvHmn9HZjtrSifjdCB2Ur7pgMEe8
         KdhHoOz7BfBQXOEMEC4l4kaOWHlbfK0magE8qRXxlzyWEvgO09J2a3WCIW8SDUp1t5a0
         UcJLv8b6cS9egGyaI/6uehZPgbGs4kvsarpTTBmeFCb9H/bcLMKAjH0j7g0J0g5356QR
         nDykAVuZ87w7aXfgRb3N0GRoyWu9EADUU3arDqOb0k5fxKoytIgrBPatMEMdXviHQTID
         b386a5NEGwus8j3QvBsOL1EjFuu9vGSXifGnSSyVRXxOAjo0E4TtmS5VJeLPFY5ZGdzH
         v03Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=cxOJV+PXw0OWe981JdPu+MdBwKVnkcb6yaLM9gtV+Uw=;
        b=kz67McjrNc86aBj6iXj1ypDBWYRo1eikX6hBVhu6iks42mi/mEyrSAn9FQnBnCa+Ie
         HSpr5wE7tCsxgS0au+mivOIpvgHXYfgvqwoT3GicZevnRu8c8EasVqKPdWrdTmH0xUPs
         QBhdzhlMQyYaIuutl8LxeoVvfZcCDCdC3lr9H/FKTkdwQd4HgkZgwwEBSOEwhUF3J4mO
         EoaF9Pq440aE7kG2A2V5ekLZ5o9gpoM9oIiNlq1z6l9Qr03fSqmX41O37eWPsDkwB1tz
         vXHdYkVw+iQ5QfDq7/qgH+8H7U+bK9//WxtHlmf4/0emrpqWQbpIMz70Gsl18DSMhLim
         cAdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Kcjra8yw;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-2.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id f17si135993vka.5.2020.04.10.09.04.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Apr 2020 09:04:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com
 [209.85.221.72]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-224-Q7hyZ5l-MvagYSWsjCIoUA-1; Fri, 10 Apr 2020 12:04:57 -0400
X-MC-Unique: Q7hyZ5l-MvagYSWsjCIoUA-1
Received: by mail-wr1-f72.google.com with SMTP id t13so1433632wru.3
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 09:04:57 -0700 (PDT)
X-Received: by 2002:a1c:6545:: with SMTP id z66mr5590628wmb.81.1586534695911;
        Fri, 10 Apr 2020 09:04:55 -0700 (PDT)
X-Received: by 2002:a1c:6545:: with SMTP id z66mr5590603wmb.81.1586534695605;
        Fri, 10 Apr 2020 09:04:55 -0700 (PDT)
Received: from ?IPv6:2001:b07:6468:f312:f4b7:b34c:3ace:efb6? ([2001:b07:6468:f312:f4b7:b34c:3ace:efb6])
        by smtp.gmail.com with ESMTPSA id j10sm3249165wru.85.2020.04.10.09.04.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 09:04:54 -0700 (PDT)
Subject: Re: KCSAN + KVM = host reset
To: Qian Cai <cai@lca.pw>, Marco Elver <elver@google.com>
Cc: "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
References: <CANpmjNMR4BgfCxL9qXn0sQrJtQJbEPKxJ5_HEa2VXWi6UY4wig@mail.gmail.com>
 <AC8A5393-B817-4868-AA85-B3019A1086F9@lca.pw>
 <CANpmjNPqQHKUjqAzcFym5G8kHX0mjProOpGu8e4rBmuGRykAUg@mail.gmail.com>
 <B798749E-F2F0-4A14-AFE3-F386AB632AEB@lca.pw>
From: Paolo Bonzini <pbonzini@redhat.com>
Message-ID: <1d6db024-82d1-5530-2e78-478ee333173e@redhat.com>
Date: Fri, 10 Apr 2020 18:04:54 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.5.0
MIME-Version: 1.0
In-Reply-To: <B798749E-F2F0-4A14-AFE3-F386AB632AEB@lca.pw>
Content-Language: en-US
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pbonzini@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Kcjra8yw;
       spf=pass (google.com: domain of pbonzini@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 10/04/20 17:50, Qian Cai wrote:
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
> Does anyone has any idea why svm_vcpu_run() would be a problem for KCSAN_INTERRUPT_WATCHER=y?

All of svm_vcpu_run() has interrupts disabled anyway, but perhaps KCSAN
checks the interrupt flag?  That could be a problem because
svm_vcpu_run() disables the interrupts with GIF not IF (and in fact
IF=1).

You can try this patch which moves the problematic section inside
the assembly language trampoline:

 
diff --git a/arch/x86/kvm/svm/svm.c b/arch/x86/kvm/svm/svm.c
index 27f4684a4c20..6ffa07d42e5e 100644
--- a/arch/x86/kvm/svm/svm.c
+++ b/arch/x86/kvm/svm/svm.c
@@ -3337,8 +3337,6 @@ static void svm_vcpu_run(struct kvm_vcpu *vcpu)
 	 */
 	x86_spec_ctrl_set_guest(svm->spec_ctrl, svm->virt_spec_ctrl);
 
-	local_irq_enable();
-
 	__svm_vcpu_run(svm->vmcb_pa, (unsigned long *)&svm->vcpu.arch.regs);
 
	/* Eliminate branch target predictions from guest mode */
@@ -3373,8 +3368,6 @@ static void svm_vcpu_run(struct kvm_vcpu *vcpu)
 
 	reload_tss(vcpu);
 
-	local_irq_disable();
-
 	x86_spec_ctrl_restore_host(svm->spec_ctrl, svm->virt_spec_ctrl);
 
 	vcpu->arch.cr2 = svm->vmcb->save.cr2;
diff --git a/arch/x86/kvm/svm/vmenter.S b/arch/x86/kvm/svm/vmenter.S
index fa1af90067e9..a2608ede0975 100644
--- a/arch/x86/kvm/svm/vmenter.S
+++ b/arch/x86/kvm/svm/vmenter.S
@@ -78,6 +78,7 @@ SYM_FUNC_START(__svm_vcpu_run)
 	pop %_ASM_AX
 
 	/* Enter guest mode */
+	sti
 1:	vmload %_ASM_AX
 	jmp 3f
 2:	cmpb $0, kvm_rebooting
@@ -99,6 +100,8 @@ SYM_FUNC_START(__svm_vcpu_run)
 	ud2
 	_ASM_EXTABLE(5b, 6b)
 7:
+	cli
+
 	/* "POP" @regs to RAX. */
 	pop %_ASM_AX
 

Paolo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d6db024-82d1-5530-2e78-478ee333173e%40redhat.com.
