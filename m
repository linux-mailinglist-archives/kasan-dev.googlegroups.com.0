Return-Path: <kasan-dev+bncBCT4XGV33UIBBH4HTXEQMGQEB5MH6YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CCC40C8B66E
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 19:14:57 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-434a83cd402sf546495ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Nov 2025 10:14:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764180896; cv=pass;
        d=google.com; s=arc-20240605;
        b=lSxZcobMjv3+e1OTklBog8CHkirphpPXVoIrcnD2lDxC35Qj7p+EjQLW8nEcBEhJWs
         X4H6mixoo8wDFV04tamAl3ZW5cWjfL/a+5v8DBCh+u/gXXoeJbJMpVnADBaNqeURboS0
         XghWjPAUmfXUZHfaFsxgFtHsax4KakHjvZGrvkbr/stutOSZ4k6jHG1osatGuqFIhjNC
         Dhv9GxMXi1yE6KeFEgrnLwxVabEMu1So+OiNhpGwbBCHgDbcFdFOXGpubz0TTTbeeeXC
         uRvH+mkAxzRT5SePu8dx7oLhVZOdBJBAAZlDB2FPKosBIjxgvyVPqgfNrCvts+uRN3rE
         9HNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1xmzP0lV+LXsLh3anFV0DWpNR0jcHYuKMWI/WlDq7yY=;
        fh=SQsxGZaVktfFKlbVesRVpbArcmjfPv8EttEsaSVFTP8=;
        b=f0AawWnLNW+ZrGiIXBPF/VVM8e9rU8+5s1bmi2uTlLk/vOlwHt3kztl8TP26+b565L
         S8+YzoC9WqiaPgKl4NRagsbXqVmOnflxfQ4rTQMKxTZeGYEhkF5c1FNWioVtaDUNKCij
         0yFAIz2dZ7BVnlPCQEU7Uy8bFhjCkqqjYZb2reAEEt5mY5vx+cd+aGClmlK1TqqNMVKm
         uu4j8ijEQuKmOQUpbMOtfR2LJKUhF/+MFf3z8yATB5xnyymeVF3X2J8pgqwsSyw45V35
         Egq0Bm5bZjmpH+CbcMfw4CmFT6BJR4T5C7DWG8eThtAnQPYnb4vVgqXN1xOpiyDf1+4Z
         N/FQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=p7X5qj2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764180896; x=1764785696; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1xmzP0lV+LXsLh3anFV0DWpNR0jcHYuKMWI/WlDq7yY=;
        b=NX4kLu7dcJMAopI0EfS/e5kYuK0QUeBR4vpHsp780GxSp1DJeT/5DOmH3aiX2NK4b0
         LKISR6Q9R8kM3GoUJShQ1IcseMyPyQqk+zrcQiPrYnUcnYngn6dXt4JAqHU/X6ta3MzO
         /peiZGA+up2ACOLUYuqC2EPTdA4AGkNbM/2a8/OBO2mw/BkJUV913sgOg9J0Ob24tnZ3
         IM7U9XHhe9J4qXetS8Uf+SsA0q2E3dSKycO53q1hy/coS46fLDLx8obMRYvSoAbNo+D7
         uq5gsIWROwSHlVq1+nvWm+3AXY/DiNmgKCcDNNaI8vk4PxtdTEr89PBX6qJZE81kcbiQ
         DJRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764180896; x=1764785696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1xmzP0lV+LXsLh3anFV0DWpNR0jcHYuKMWI/WlDq7yY=;
        b=fgqqmAsKs3fevverYVTPDByRXwD5Z3xY34XKtdYTbsWSUOIGulWVTTr3w5CyeYj2ds
         In51D4or6SQ1VHpxyGsg/OYUVtPeZIFQSBW9rm+W+/kvyTmxgeVfND9QYi99IF0miWMn
         Prx6Ahp12bNLurVNqnFqgl4rtourgWQ4uVNtSmltcOw8mnkchvRPXahY8UbJYyGlqbD9
         dYaK7SA7JW7lwKkECoFPyh6PI+LUAzKRfYkYDgJGIuwUjT1VMGIHOTGspBRrmUCiJz01
         bFs97xQd5Wmn8tPurr4v8Zh+aUfcBFXbTOXCrfWd/MltzdtRnN6ZDDOhqFsUF9pf79JV
         ifSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWCV0C70Xs4dYSD90M39JTR9eNa5taKKN3wqMwLP2N7zY2bWHRMWkfw7ce6uwDSm/rSrl8BiQ==@lfdr.de
X-Gm-Message-State: AOJu0YwYz6dvB+LUmPR4tmwGH0wDrgzRVZTZ96V2cR9U2wMt/obI1Pc3
	4QGqLGvzcHpqS3Z1NCSnryviuh1cPYZumGWi2I03sx/8VwhA78S/VFhV
X-Google-Smtp-Source: AGHT+IE1/36CpESR5ggMSNo9hZbHr/o3rhhMrIEJOhC3uL5N8lbst2usTTLceqpyUGh8zRtbVFeBkA==
X-Received: by 2002:a92:cece:0:b0:434:a88d:f805 with SMTP id e9e14a558f8ab-435dd043b35mr43372855ab.4.1764180896102;
        Wed, 26 Nov 2025 10:14:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bTgKUQCaI4wubP2HrDKQ9AEiBZRGxHK8VuSOV+VY9ZwA=="
Received: by 2002:a05:6e02:1fe8:b0:42f:8b38:c20d with SMTP id
 e9e14a558f8ab-435ed40d634ls308305ab.0.-pod-prod-08-us; Wed, 26 Nov 2025
 10:14:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV5qM/rwAhPUkoggTPPXsVt2n2kX/2WPzoEMwUE0m5TdBOLUci59o7SPny2tXTr7Cs3/VBrERhlgR0=@googlegroups.com
X-Received: by 2002:a92:cd8b:0:b0:430:c90d:10ae with SMTP id e9e14a558f8ab-435dd119d26mr83112635ab.32.1764180895003;
        Wed, 26 Nov 2025 10:14:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764180894; cv=none;
        d=google.com; s=arc-20240605;
        b=TLuHXS5hKYbI2LJ//2iHrvKYzj09+Zf7fX0Fj07ScwVLXrEIwQDoS1O0uigyAvAB/F
         mu0FhQaKEQ/6FJYZtYpFtkUN0jn6BLBnzU0qToPcNtItpCIi0qWItfCrTb/kR0m1Ma+E
         Fk2tGQLCLju833QkDipBXZg9QBOHQ4+bAwv5+PRyup7vDHXuRTtdBzLRodnFPTamPVDR
         aHIzFrAVhQNT9S925OkJ8PH3u2x2KAqPm/ZdKwWkOp8tlYhTH9kEOu6Dfm4JfEe2NaQq
         BqrVwAEQEQDo2wvGmCntU09TV3a5EoXEOnqO04mmGfJSn3hXr/ercxfevTLNXNrrYT21
         s+7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hpmpWmbnz8Thf8qOhc0rH9R++NsLdv8emSQl3kXPtik=;
        fh=UaJGxuFybwe1NskxHfCsG66Q3oBYKTBpuGPjp82ZYLI=;
        b=CHnlnqeadBNUrKrbHUBgoy1lerfKU3R0pB0qE/ixYCFlCAsVZwlsi3qH1uN5BV/U0P
         HvFyGYXvyfQ1wAI1TLcpaZXq7J+u1v68CgHjlSLhhYramLG1fPzT8AvaHakIHPjv2IUN
         Z5aC0zaTWrF0FcTp2jUOTF8o0p/B2mIHLX1ofLRD3LNiuLWS42B6LGJxCcxFZcPCQ6Mw
         YnFDb1sSogKxt/sYtdDxRm9PBtGp5zf9GMhGpkvgjyTrM1hHmemhvilCpHuPip0eXKOy
         wJqmQmMYlaiaXnimSuxA/G4GvQm2OJUrbUwtV+q2W8J8EAeO0HcwkjuuB2M7/EeGy50o
         qdUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=p7X5qj2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-435a90a9526si5444455ab.7.2025.11.26.10.14.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Nov 2025 10:14:54 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 544A6435B9;
	Wed, 26 Nov 2025 18:14:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EFBC3C4CEF8;
	Wed, 26 Nov 2025 18:14:53 +0000 (UTC)
Date: Wed, 26 Nov 2025 10:14:53 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Breno Leitao <leitao@debian.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] mm/kfence: add reboot notifier to disable KFENCE on
 shutdown
Message-Id: <20251126101453.3ba9b3184aa6dd3c718287e6@linux-foundation.org>
In-Reply-To: <20251126-kfence-v1-1-5a6e1d7c681c@debian.org>
References: <20251126-kfence-v1-1-5a6e1d7c681c@debian.org>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=p7X5qj2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 26 Nov 2025 09:46:18 -0800 Breno Leitao <leitao@debian.org> wrote:

> During system shutdown, KFENCE can cause IPI synchronization issues if
> it remains active through the reboot process. To prevent this, register
> a reboot notifier that disables KFENCE and cancels any pending timer
> work early in the shutdown sequence.
> 
> This is only necessary when CONFIG_KFENCE_STATIC_KEYS is enabled, as
> this configuration sends IPIs that can interfere with shutdown. Without
> static keys, no IPIs are generated and KFENCE can safely remain active.
> 
> The notifier uses maximum priority (INT_MAX) to ensure KFENCE shuts
> down before other subsystems that might still depend on stable memory
> allocation behavior.
> 
> This fixes a late kexec CSD lockup[1] when kfence is trying to IPI a CPU
> that is busy in a IRQ-disabled context printing characters to the
> console.
> 
> Link: https://lore.kernel.org/all/sqwajvt7utnt463tzxgwu2yctyn5m6bjwrslsnupfexeml6hkd@v6sqmpbu3vvu/ [1]

6.13 kernels and earlier, so I assume we'll want a cc:stable on this. 
And I assume there's really no identifiable Fixes: target.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251126101453.3ba9b3184aa6dd3c718287e6%40linux-foundation.org.
