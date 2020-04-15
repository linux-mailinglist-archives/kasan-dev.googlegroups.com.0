Return-Path: <kasan-dev+bncBCFYN6ELYIORBWO53T2AKGQE3M7QXBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 920891AAC6E
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 17:57:14 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id n85sf16362264iod.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 08:57:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586966233; cv=pass;
        d=google.com; s=arc-20160816;
        b=gJec+NJwVnssCkmivcQNxsn8LIC0+KGaUgjX0/E5AROo3YFRNDAanjDExWPI5rylhl
         s6BnVgG2RJwiTzfV0u5ZyiOnv9s9sueYaIue4t+CWfG8ucMGTQcfm5cZFH6dRyP1jk8W
         0mZn+Y82dRKGzwGWThBJYVhCAG0VqVhu5r7xooIv9WY9WHzpJ3mjLzNvf9PirmqZc6Xe
         6tJCOQS0S/W+NQkI3VBHACCEZVoUIhBczwY0dxiXun4bAGf4/RQznGNkMdDe7qbBVdQk
         Tt8N66X9kWklLxmnqmzr9M4M+uCHPr0YgmaxyQKKgzKepLlhzRF9ey2qL/HqHXtGwtyM
         q9Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=NhryUw0n36klZwNEsz3nem7L5dmBUSaKzi5YYvdgEHo=;
        b=E8wPPWW/4j1zn8p7Sr4xY8DzVbdPXAVA4ZrlK1kz5LJ/VAp/efDEOyvtKUseTDQTAB
         14EpIrVMFbKQZNOt+mcSIngk/6mJgBn1J5/wszFguGbH03amiqRJWWY6wdDO4m+vO+1S
         6Z/BC5ZduBttY35ceeMyGLGOYQSCogPJESVuk7XsLxjWzNFJRWjfRpBIt5uv1TVyqSPv
         n7oAX/St9/Wwv6FfSEGjbUpHyCIPGgj0tcmmK1jSWcFQtCCuwj9fTc+1bpxdurD2wjno
         9GiVtonrZL41oj0KahcOtmUZHXlggfioRhDh9e9bK8JWZA+YS45E2tODHeEph4qVIlX+
         N2fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=aNPF7aU6;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NhryUw0n36klZwNEsz3nem7L5dmBUSaKzi5YYvdgEHo=;
        b=qYnO8y3Fdulo7EPzYeXEEl2nWLBWX+EddW5q3KcUn/9IDjMgY0HOGPf/B4rfrb3VpE
         kMAMZgoomV3dSxDwn1o3hnhOwzvqklpJEBGufYgYqS+KgqFBP3SWfygIh2ACSiuB4lED
         8Sw/mzreKylgbeWjX+2P/jrDhvpv7NTK/7i1P7WGiVy7U/FT5z1L3bIy2rENyq+wWFQX
         DgF301R7jT934gFOjvBOYJhL8vaLBFJZrrdQ5rSa/8kDFHVSz34eXrnKk81j2xfX6Jew
         8ogbT1zF/vlylZCnpxclefdRlw9ZDTxx29ZWgFHEmCN02mjG/DCOoIRngCnHpAiec1uL
         lkFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NhryUw0n36klZwNEsz3nem7L5dmBUSaKzi5YYvdgEHo=;
        b=s+vKGrhXwVMf6irE8loWWgCLeojwQDsx98rxoIsKjzCz5bdJ0Cx2zgD2AU0WapCywd
         VquhKkP9sD45xE90n839EknjmpGR7n6SuNOG/rMDUQlKjlVaQ6pr1mAxUo2+YxtPW1RU
         B1i3tBCuI8/uceKheBpf7IfZjs/U/Gn6KTMx+J34ysrCbZvwS01JVh37VlrmJRGV4aJe
         XLr03jvZySbhD70RWKu/l7rmiEg8Ef+TT/aGhg7rEIxijjFYJMgCp/qsK1nD5ulURuWg
         VWdBGQDsvPM+TWmDi/DpSGav5rv/yUg7gQZSoVmgJXesHzy4szmW8adfux1snOEnQLdm
         wjtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubzXzPVhVP6ooc8YQHDQUj033K7/LnA2t3G1G2iUt76JSZrQCJB
	ju6BUztjQNUGFOXxKa63Hu0=
X-Google-Smtp-Source: APiQypIEgtbi1d9We+JEUXK7V2pYUT/GnPgW7Q72OIwlv6BZltSSyRv201gAkJNGhIEA+s1DKmTEWA==
X-Received: by 2002:a5d:8b57:: with SMTP id c23mr26849395iot.161.1586966233447;
        Wed, 15 Apr 2020 08:57:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:47:: with SMTP id 68ls1565075jaa.9.gmail; Wed, 15 Apr
 2020 08:57:13 -0700 (PDT)
X-Received: by 2002:a02:c725:: with SMTP id h5mr25901096jao.13.1586966232786;
        Wed, 15 Apr 2020 08:57:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586966232; cv=none;
        d=google.com; s=arc-20160816;
        b=nBkd3uukSObCdGFvwl+pLB7mNwZyaHdHrJSmcK8Iif/hoW3jmxDZ4Hlmw++ShMnMB7
         2oD12893NRYoaUZAfR4R9FNEHGUJdf30FH0QJKoO6XG8vlVlLJcg25y4qClFOqZJHPEA
         y/Z8nw14qxsve8+3LNnlR0YWLXQGRtIptdo6fdM+TvZSJADKF+kECwrjsqO23h+6cgPu
         F5xAJARP2axo6pLuqwlRYFNDiWcTlkSS6J0CvBuWZqBVPEN8Ok5xXo1mVWzGoOnYpu5Q
         T6nUSxNSPXQOtIG/yweVb2hOtZZpieRPGykl1+zbW3K9VVOBw3G7XGOHhDyoA9pa3z2P
         2xlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=sWwTwNA7+phf5J6ocjP6MH/fyRWY0vqsvDmTIUNVg/c=;
        b=ZHzwTYTOTv+PlEkT3mIiINn+CG5iz8xlcml2M9Oy1PDdzyiL49iDZ1wsznDpr2fWj7
         doYrYi+3ML6TNZk7L3c0SCg92knO+GlnfkF67G+i/kOv9m0iB9Jm05NnsenOxfphPQgf
         WE4zFwKnVTVWLtOF7m+lH4wvLuSuXZpdXKhbTATF3VoeN+wRwhQ06ndBBSH2uTiAk8uB
         rR3T3YjX9UBC1DCu3gtXaHIu2pkaLBGg4zjnbX6usE/J6mKgU8SpGN/s13riFk8At6IK
         ukGYMZgL+xBjfbQbvLFCDrxMuxD8z+1eS7TGIfOjwYuksLbA5E/iRV9eWik0BbIVUQOU
         tGKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=aNPF7aU6;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id x16si291700iov.1.2020.04.15.08.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 08:57:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-310-8iFAtzsHPV2hil5bdsBOlw-1; Wed, 15 Apr 2020 11:57:10 -0400
X-MC-Unique: 8iFAtzsHPV2hil5bdsBOlw-1
Received: by mail-wr1-f69.google.com with SMTP id e5so108438wrs.23
        for <kasan-dev@googlegroups.com>; Wed, 15 Apr 2020 08:57:09 -0700 (PDT)
X-Received: by 2002:a5d:634d:: with SMTP id b13mr19463055wrw.353.1586966228729;
        Wed, 15 Apr 2020 08:57:08 -0700 (PDT)
X-Received: by 2002:a5d:634d:: with SMTP id b13mr19463030wrw.353.1586966228418;
        Wed, 15 Apr 2020 08:57:08 -0700 (PDT)
Received: from ?IPv6:2001:b07:6468:f312:9066:4f2:9fbd:f90e? ([2001:b07:6468:f312:9066:4f2:9fbd:f90e])
        by smtp.gmail.com with ESMTPSA id v21sm12010wmj.8.2020.04.15.08.57.07
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Apr 2020 08:57:07 -0700 (PDT)
Subject: Re: [PATCH -next] kvm/svm: disable KCSAN for svm_vcpu_run()
To: Qian Cai <cai@lca.pw>, paulmck@kernel.org
Cc: elver@google.com, sean.j.christopherson@intel.com,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org, linux-kernel@vger.kernel.org
References: <20200415153709.1559-1-cai@lca.pw>
From: Paolo Bonzini <pbonzini@redhat.com>
Message-ID: <f02ca9b9-f0a6-dfb5-1ca0-32a12d4f56fb@redhat.com>
Date: Wed, 15 Apr 2020 17:57:07 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.5.0
MIME-Version: 1.0
In-Reply-To: <20200415153709.1559-1-cai@lca.pw>
Content-Language: en-US
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pbonzini@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=aNPF7aU6;
       spf=pass (google.com: domain of pbonzini@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
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

On 15/04/20 17:37, Qian Cai wrote:
> For some reasons, running a simple qemu-kvm command with KCSAN will
> reset AMD hosts. It turns out svm_vcpu_run() could not be instrumented.
> Disable it for now.
> 
>  # /usr/libexec/qemu-kvm -name ubuntu-18.04-server-cloudimg -cpu host
> 	-smp 2 -m 2G -hda ubuntu-18.04-server-cloudimg.qcow2
> 
> === console output ===
> Kernel 5.6.0-next-20200408+ on an x86_64
> 
> hp-dl385g10-05 login:
> 
> <...host reset...>
> 
> HPE ProLiant System BIOS A40 v1.20 (03/09/2018)
> (C) Copyright 1982-2018 Hewlett Packard Enterprise Development LP
> Early system initialization, please wait...
> 
> Signed-off-by: Qian Cai <cai@lca.pw>
> ---
>  arch/x86/kvm/svm/svm.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/arch/x86/kvm/svm/svm.c b/arch/x86/kvm/svm/svm.c
> index 2be5bbae3a40..1fdb300e9337 100644
> --- a/arch/x86/kvm/svm/svm.c
> +++ b/arch/x86/kvm/svm/svm.c
> @@ -3278,7 +3278,7 @@ static void svm_cancel_injection(struct kvm_vcpu *vcpu)
>  
>  bool __svm_vcpu_run(unsigned long vmcb_pa, unsigned long *regs);
>  
> -static void svm_vcpu_run(struct kvm_vcpu *vcpu)
> +static __no_kcsan void svm_vcpu_run(struct kvm_vcpu *vcpu)
>  {
>  	struct vcpu_svm *svm = to_svm(vcpu);
>  
> 

I suppose you tested the patch to move cli/sti into the .S file.  Anyway:

Acked-by: Paolo Bonzini <pbonzini@redhat.com>

Thanks,

Paolo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f02ca9b9-f0a6-dfb5-1ca0-32a12d4f56fb%40redhat.com.
