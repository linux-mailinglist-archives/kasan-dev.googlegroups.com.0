Return-Path: <kasan-dev+bncBCV4DBW44YLRBPUA2PXAKGQEYERANSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 73A3E10327C
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 05:25:36 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id u10sf17920391ybm.4
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 20:25:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574223935; cv=pass;
        d=google.com; s=arc-20160816;
        b=TA8IpGdrvE37npZgDF1rRPPkCYTU8lAmyFOP4YXQLNjzbbd4+fO1GN0BwGD79N7aY7
         6JQhYEgsi+VQgZUqyzhfE99lQ/3kWZ4jnRSkprzFjxDGaw6EzWxTJUwbIXUgiVbofR9f
         R/XHhXSMermVMZL65ADzVmThbz0Me5L0SbZtaV4VjiaVDFo7oMbqpcD66gSvd/eJC8Oh
         i5gN9vGcZ0HOEJlFrUgKCKsGo/fppzGOilRH+roMjaRekptHGx8z3IwVfVvwG9TM67L9
         EXxQ/382F+jEqXOY2VbX/pXxChkCMUdJZ4Xf3g7Dv2ynUs6UCjRr23XohOo+HVtAGqfk
         ZF5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=ts8xQT9sMtmyMKpy5kbvILk5hcq9z5RHQ8fivDVSKak=;
        b=NKKcxNc5B9w+nT/eNylsjZHeUDYS2UqHCW5D7cP4236AGiteS8MBoHEavmGpESZRdN
         Q3LRKiw/MIWu6m7XWMIQWbOKZelvUyhxzRmQn4EMbCFkHSjtY4wUDdMpTIublqjcEvHr
         b5PYHCd/51OsAzedh8BJSzycQzlD525sip2TuAffrxxi9ZQFtv/P4kDtqiSKptJEsGiB
         a61M+iQJWRI26EuWqIli3210QeOlczLDmc4kbFoL9RowxMF5qfKIadB4ZtYPh/W8SwuZ
         OhZUqXRw4ezeUcu/1ltstG7Bh/QBUPPOVVG0Fg+AZdR0o/Oa2o6LPN7+Aoa7Ht4dEBrD
         Ix4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of ak@linux.intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ts8xQT9sMtmyMKpy5kbvILk5hcq9z5RHQ8fivDVSKak=;
        b=JJzAxZmxk9+JkKOCHZzTrLKu9UKrFxC/dcZVNYlLmYMGR+R9gqSYgcQ6BrRGFr6Eat
         As+mcnGpRT3kNZXBsxLylGBngkw1WJnxM1ON2QPbksd1p6/PgykIoifSNxwikT0kIyQ2
         WYJA7XXUcDt2CvJejqkGNkhsnKgPd8xVc45pIKXhjZCf1L+HLvnp5bmFHq5dRtpAkzIu
         Ae1PamPVJmCxiICteUlMCentz3MDQ6z5PjxAtPY2FjiFR1+LBL+vdD/6hfzsbV780tfI
         MO3nj8JtR/9N15/MAbZSy2+ZGs6GN3ShZcMhFyUW/m29ysByJL55ZLspmmf4GP9doR7f
         4NNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ts8xQT9sMtmyMKpy5kbvILk5hcq9z5RHQ8fivDVSKak=;
        b=HzSZpbS0vsC4GONGvVdZRDEbRxUk/n4nGoHhCzi164iHIjlnRqOVO9Qw1yl4v0/pws
         4JmqXMyo2aTxd0aPl97Ia+5Pi+XLebnwuKL4+MAnlmYgAkGxt0WdYCd0WGxV7mbpUSzD
         MwnSHUfADcrgLNFMII396TOHuRMMjLMPMGei0AW6ja8Vy3m1rPycGSSQN/xHH6V/LfAt
         DLdoTdSW4nqEzWTek/O5sQPhvAx6fySyBJuRU0MhnKWGQpKSI+BrITjS+wGWq8dMw3uS
         7PZmr8BpOk4WE5etY6rTnFwGF+DcH6osGW7A4QdJdYPDUhPJ03vCy8ioNYzZRT61UcD4
         mImQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWOpTY1l5oElbM/TNxacH36oMrRG7OShKMYd51e7CtoQ2pGKbSl
	rX5JJIRriGuy9nlMOGbzqb4=
X-Google-Smtp-Source: APXvYqx7bBTxJYWevLeRlNWBSrkCsbDyoh8ZM0Y9h5OIv7AIh1D9OLTSMjbCUVlvrp7NnRJHUA/MkQ==
X-Received: by 2002:a25:ac8:: with SMTP id 191mr544409ybk.396.1574223935079;
        Tue, 19 Nov 2019 20:25:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:1445:: with SMTP id 66ls178357ybu.5.gmail; Tue, 19 Nov
 2019 20:25:34 -0800 (PST)
X-Received: by 2002:a25:646:: with SMTP id 67mr555376ybg.492.1574223934689;
        Tue, 19 Nov 2019 20:25:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574223934; cv=none;
        d=google.com; s=arc-20160816;
        b=DDOO5poZVS1AqoQGy0FEeRWCqD7a+LUoYADeg98py7eeLzattsr9cpwlwz/WEHW2v4
         Ss4Y/+wMkQ1qZ27NHrIVwBUhCX1/IK9qAVAdhe37wb9RNr3RhoDMPiggweAKA0vIyuAQ
         OTBymV0o/l0P8TJIYgTsDr0lpMl9jtjAc9aLFh2Uob3crYyU04sOJ7M2WVwn4uPQUAIu
         Wz+u9foV/O5EpvyWCNkVHV97UgbC7iBjEPR7pJ40FdprsdF0CIla1KJbG6ltUOI4g/QV
         +2IqK38Ep1aFsDl0p+Zaw2BZgBATb5KC4UKvglmEgi+nl64ay0Vgt9YI7Jx4xMqzM6Ir
         7JWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from;
        bh=ZJs8pZhKJiLq0G1GDQdqyl4klhHAXAHZT9LCaPqSJOM=;
        b=knSu1cfkwNSyYbOHmm223hbUthboaPDCbjIAIMgsGc1HHD2PDzTslW/BsMi9jgbZj/
         QsVbbKNnrrAI81xAkFmWTPJXtm+aR/W9BQYPza0ekM8J0PXLjST8T+et7xx3okSGc6YM
         CQLocX6bCbGxYeaaFoF+f2Fv+8E2QC7ZAXODJNS+DUDZRFoK7uQjrRXN+mKBwuoibG3L
         MuIM2/WEiFLHJ/xt15pyhySYBgnHXtx+sPl7NfRQVCENcTnU4+gGAeMcRDFMv/d64rxZ
         XKpcVofhqTQJHWwY1DEDNndCXbphiwBJ1I/jlEaclolm5yNL9JIt+0PAwmVBiqjqzsMk
         t9Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of ak@linux.intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga06.intel.com (mga06.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id f11si1372385ybk.5.2019.11.19.20.25.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 20:25:34 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of ak@linux.intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-Amp-Result: SKIPPED(no attachment in message)
X-Amp-File-Uploaded: False
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by orsmga104.jf.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 19 Nov 2019 20:25:33 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.69,220,1571727600"; 
   d="scan'208";a="209625675"
Received: from tassilo.jf.intel.com (HELO tassilo.localdomain) ([10.7.201.21])
  by orsmga006.jf.intel.com with ESMTP; 19 Nov 2019 20:25:33 -0800
Received: by tassilo.localdomain (Postfix, from userid 1000)
	id 440B330084E; Tue, 19 Nov 2019 20:25:33 -0800 (PST)
From: Andi Kleen <ak@linux.intel.com>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,  Ingo Molnar <mingo@redhat.com>,  Borislav Petkov <bp@alien8.de>,  "H. Peter Anvin" <hpa@zytor.com>,  x86@kernel.org,  Andrey Ryabinin <aryabinin@virtuozzo.com>,  Alexander Potapenko <glider@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  kasan-dev@googlegroups.com,  linux-kernel@vger.kernel.org,  Andrey Konovalov <andreyknvl@google.com>,  Andy Lutomirski <luto@kernel.org>,  Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
References: <20191115191728.87338-1-jannh@google.com>
	<20191115191728.87338-2-jannh@google.com>
Date: Tue, 19 Nov 2019 20:25:33 -0800
In-Reply-To: <20191115191728.87338-2-jannh@google.com> (Jann Horn's message of
	"Fri, 15 Nov 2019 20:17:27 +0100")
Message-ID: <87lfsbfa2q.fsf@linux.intel.com>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ak@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of ak@linux.intel.com designates
 134.134.136.31 as permitted sender) smtp.mailfrom=ak@linux.intel.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Jann Horn <jannh@google.com> writes:

> +
> +		if (error_code)
> +			pr_alert("GPF is segment-related (see error code)\n");
> +		else
> +			print_kernel_gp_address(regs);

Is this really correct? There are a lot of instructions that can do #GP
(it's the CPU's equivalent of EINVAL) and I'm pretty sure many of them
don't set an error code, and many don't have operands either.

You would need to make sure the instruction decoder handles these
cases correctly, and ideally that you detect it instead of printing
a bogus address.

-Andi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87lfsbfa2q.fsf%40linux.intel.com.
