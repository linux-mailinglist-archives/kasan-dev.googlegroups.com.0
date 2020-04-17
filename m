Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB662432AKGQEN7562JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id D4F061ADE29
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 15:22:04 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 33sf1616526pgx.17
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 06:22:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587129723; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQHeu8WOEiH7Idhx6NkjD2ZEmFttEGVXfQei7deyWzuN3ZhbvU/ZFOHzV59oEV7fDo
         5BISuBNYFDw3C8PigEvK6+BgSD9mvRScvVXjpluT0GvKRDkPaUdgQrGoH2aIcp1DNMrH
         kfjsHnSgdIjkchgnogC5HqOfZgTCcRIw30dyjyS2EQps6sO6RdBRHcumj2DjPRNmbMFS
         gJ3tRu2wFMwE7BD6YDNkk771qNjWUnM9LlgOrmGtUDflY477dDB5nkxNVf+NYpnq1/AW
         6M89zFUv2WmRsSSrFBcAvWxNqMuof3bVIu2o34uc8G8v1jJVv55IT2EXOTosAhFioEPf
         phVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=wrGaV/Lf7QeD1S4bcg21NkiA2kaKd2MZeNc9YR7Hr2Y=;
        b=jrsT89zwazE6Ciu6Z+11bA71KNYWKli1tVNEF8APxXtLNAqbNHL2P7lf7Puv/XtKI3
         is7oLQNox6U8NI0WsjY4/89p/iU4SneWE+6zCesEkNMDbe8shZSV+AWcJRJ4i5O2HeYr
         9Iaf/SrUzUXannT/7tdD5ZA7+Nd3/NQKGa9ycnCgPYnJPSdBE5tIZt4C0E2eOkWKV8uN
         kDgwNscSXFToKdMIIj0OFnlpYwWHgj5C+ygnmF90cS+0ldlq5CdQkIyVzv1XX70hZcz+
         m3deNfwop/yFK1YugzpDWt12Mc09NN2m6DqPFIPqi3C533Z09L0Gzg/MX/uleB6P6OW8
         T/6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Cy4c1ZQe;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc:message-id
         :references:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wrGaV/Lf7QeD1S4bcg21NkiA2kaKd2MZeNc9YR7Hr2Y=;
        b=ON3dBefGj6ow9cMjoV88/lnQJgTFJZUxUfgjNpsW8qwLOlodh4dwyK0uGOcnd99zLK
         SSX1wFD/nhRPVj2Wh1y2M4+7IFJ5DJF+Ej+CRIaVpFIUZGhE8flkPUa8p09fqrTHvmMm
         wzj8cTESxG2JCNEjUKYIn54n4gFKi3AiC3BqpAhkaGqB66N7biHcbz3Gf3iVuEHWwOVQ
         l0cFqcqp7u0+qzKtPmqox0Oo0Ec0LPtJJBWhbsZmTjZUOqvxiQP9Aui084XOgvVuCHyF
         kv3LLc2uojbAT6QF34xyfC+sSaLiVNV+qbbSc+rwoPuNQu5c2z15jfchpKomkO8gqdBJ
         yfhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:message-id:references:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wrGaV/Lf7QeD1S4bcg21NkiA2kaKd2MZeNc9YR7Hr2Y=;
        b=ORe1q537yP9hlwm/5StB2G2phJ/S5Tp3frluBSmVNKwV/yPJJTTh6x3Q6f6cRoJt4q
         1O9mENyIgWnEXKO4TMNWCrSOtYAzDdNea4UDW3tz7oAlExPP7QGmP2ISecVQCptQulBo
         HmKwruokZDOBw6XoOROV2Fy6gieyV1099oZJYKXURBqdoEJ27o/kyCJlJ2sctS1cDlUW
         MIqKX9dYBnqYAuR+JvcOPhvLutek9P+O7wLC45BstWl/JleuUEE2wppS08lnBiEjQCzq
         NpcUtt0cRhnPe114nMcilIP4ciqWCFR7QWYd8DzmTwEmV/BSmW1r7gO066W82I9621Sm
         +OyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Puaj8oXfc9UtRNse4bR+B+VAjPcZW2/9G6bbqIyEiORT54ILwRh4
	+L1PbwviJDec589N3nDpjug=
X-Google-Smtp-Source: APiQypJJlJ7Tx9AK5f1GP0SGcNZRXLPEjTFpchSPxd4Bt7uUBDxHc4DS5DYboC6iMQ83p3bYPLLPkw==
X-Received: by 2002:a17:90a:82:: with SMTP id a2mr4648667pja.47.1587129723154;
        Fri, 17 Apr 2020 06:22:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a98:: with SMTP id x24ls972184pjn.0.gmail; Fri, 17
 Apr 2020 06:22:02 -0700 (PDT)
X-Received: by 2002:a17:902:b617:: with SMTP id b23mr3659701pls.194.1587129722717;
        Fri, 17 Apr 2020 06:22:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587129722; cv=none;
        d=google.com; s=arc-20160816;
        b=OGg6v4+ERD3kERrtTG5KZMMZ18j2jc9phLC6/sazvGeTS4eH1Vj+YCa7CT+4Ms8446
         5kpew+c19rkNbs4L4ziQIiBGp+zx4DDisj2CE6m8mxQ2+CN2QOvk/DbTYn2iD4ZyPQAJ
         Wo1veL2CBsq4NV+hfYGJt0iKGpdqaHhB5z+/5IA6HVlqtvBqmoWI4T80eIsfIJUcGu7q
         QS87YnnSS5vblDvD4F9ZF4tp5q323pRPLPnTmRBXY8m2R+TKzXlISj5zUGi3jJw2VVzf
         mhdAuIErC36aI63kgbYgTtbGTzq+YvCS2FBUmyib/b2bpKA3n4TtqxXSEHeWrn6GsM5S
         n80Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=Hprasaok50MZK/a/feo2e2oclDOFVapOraKUc6PEaaw=;
        b=q3XzY22ShDQSmfOokR0R4re+Bdg/2c13B3Reyvh2dH0b8d/G5DhePXNGgsUIZR+gvV
         69RuLmhfakmVujgeeWfJdYWjLEusrsE/II3ozD4qYjL2UYn29rb5GznnfkKWnpUdjob9
         A8dF4IY3Vzxej7ho+CP3uZ/0C2gbUOxiVxNgB4IpKhzCddgRfqWCo6EnYXQvQ/39E7PX
         pCQ3I/u0D1vwqbnywMp389EoxvY5SByG2h/pfcG0ooOWLm283RPeOG2a1MjL5BY24cNm
         ewo161pYXjeTZxqw7s5j2S7gyVRg6rxuHoVoDLAv4jLDb8mom6p4EjrmmjZP3V7+UFZp
         0Yew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=Cy4c1ZQe;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id ng2si344864pjb.0.2020.04.17.06.22.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Apr 2020 06:22:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id x2so1896867qtr.0
        for <kasan-dev@googlegroups.com>; Fri, 17 Apr 2020 06:22:02 -0700 (PDT)
X-Received: by 2002:ac8:46d8:: with SMTP id h24mr2932189qto.352.1587129722173;
        Fri, 17 Apr 2020 06:22:02 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id v76sm17479205qka.32.2020.04.17.06.22.01
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Apr 2020 06:22:01 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: [PATCH -next] kvm/svm: disable KCSAN for svm_vcpu_run()
From: Qian Cai <cai@lca.pw>
In-Reply-To: <f02ca9b9-f0a6-dfb5-1ca0-32a12d4f56fb@redhat.com>
Date: Fri, 17 Apr 2020 09:21:59 -0400
Cc: Elver Marco <elver@google.com>,
 Sean Christopherson <sean.j.christopherson@intel.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 kvm@vger.kernel.org,
 LKML <linux-kernel@vger.kernel.org>,
 Paolo Bonzini <pbonzini@redhat.com>
Message-Id: <1F15D565-D34D-41F5-B1C5-B9A04626EE97@lca.pw>
References: <20200415153709.1559-1-cai@lca.pw>
 <f02ca9b9-f0a6-dfb5-1ca0-32a12d4f56fb@redhat.com>
To: "paul E. McKenney" <paulmck@kernel.org>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=Cy4c1ZQe;       spf=pass
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
> 
> Acked-by: Paolo Bonzini <pbonzini@redhat.com>

Paul, can you pick this up along with other KCSAN fixes?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1F15D565-D34D-41F5-B1C5-B9A04626EE97%40lca.pw.
