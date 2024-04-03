Return-Path: <kasan-dev+bncBD66N3MZ6ALRBQPAWWYAMGQE3HQEKOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AA0F897360
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 17:05:39 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-220ac2258bbsf10903573fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 08:05:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712156738; cv=pass;
        d=google.com; s=arc-20160816;
        b=gsMaOGbOPbiX18VhtqINg4s1hgBxSO007fx0l08eCs1jPpTDVA3jsCpidLHkvH+W9d
         wMRnPVdAyTvw/ZLc7WNvLioN5A/n/daJcY1R5Lrqp2iACvGghoPW2Ovn2re+0U8DUbHL
         sTdzDzec9Z3HIuuvMhdO1p8IjnDcll/GpqXZx+KSY5hjvmfYVNQZd2g/fpIqJv1c1rsm
         OwOX9AsADHr1/AO1exmEnW3TcY5EAvAbF3SzxxBaU28bZiOUHakc9bec8Cza5sKo9d5x
         d4m8+vPuZkyEK6xuJRl9VevfE3J2zgRfXCPBbl4X+OltyXNf5GkMZYdQ4KUNfWNAnAOR
         eSKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cLWvV/6jETGC+W9DbEVVFqiVabMBsVCRPw2kXPuwAXk=;
        fh=W4B6LXwgUYFjKNAVB/tYebqpBTJkInXRgBckB211I3A=;
        b=p4FB579VwKu2HclHxweNKxZZLPZclrloxdvEaSNLznjgSIRLwwoZKYJh11Z5dM+68L
         3QzV7mvf4Sze+W9IxUh2XF6IPam+W3zfUdILGkFGUkHChtXaUNn12JWPtiIbjnIOm5Ks
         JcjTaNSgrMzLAFxZ+i3kstqqTucT5I/lDr+PllfgFzDuJePtpxBKq9NiHYFJToqm1htS
         mRACXq9aRfDMyaaWz6UPbvtepi3khpQFVVN0n8lLlD5iE6SoOXR/5VOviekp0jC7b+Mm
         p7AGJbHZM8ssgJ5y+3wwFAwcAN/dbUARfoZPH/CLtuTWuSYe2oY0z9SXoDX7paha6n0G
         Jubw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bkJRxclQ;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712156737; x=1712761537; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cLWvV/6jETGC+W9DbEVVFqiVabMBsVCRPw2kXPuwAXk=;
        b=rVQaTL3yri/oec6leCkzRBAcvO2yJYlBLVci4eZTDcmjdXRHHrPotaDdj7WQ8i6OYn
         pybLINUDigksSM5Q4g8qg3Yc8aHxAbvqTn64FzeRmCGaWLnJKBkSiphyVd4Th13wSiui
         NncKWEeiR7GHaGUPmoLbL2DsGzAWENk012jv1jUUITTTnkgwF1665bqk5TMIPIR1A8yL
         z2YDxl9Q0832aqROJpuK4xKxH0es0u47avXzlYeUKLWDB049pBHvFJNJAS/tincMVJC3
         Pk325xZk64YeMNTmJIY9b7xYtVeEE5L5i+MSeNZvI2oLvUhr7CacThWYEoJOEwtKf9dB
         5wuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712156738; x=1712761538;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=cLWvV/6jETGC+W9DbEVVFqiVabMBsVCRPw2kXPuwAXk=;
        b=nBceekF+hqTy8ejOZI0VLWeS3w3K/vf6rUuWv6u1L9BW99jyGS8e0V/PyTjIh1DiLQ
         C8XguB9bOivzVCGqlwDvNew1/XV2kNRlchvThSNR/r5W/OF634+HJwcSlSTFDddyDfJ+
         iWk4U3iI6lbnhxfnbCKckPJqI21ShQBCRgrJTv0rCNgFyyDTIr66vJvTulKGBv+KzRc8
         xtegX7aWhfktr3YFOycQ/HQjUZm8Pv+TSWFVEmGo9oyz1+uvMzfi5j4hl5xceS2XAkee
         VgD0gJhYEahtjRrmCzjdfOUGz7CfzHT3JHCB1oEVfYvoKjHK6KvuA4H8EnMI6H5Q0o7M
         icCg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUK3dl0XTHqtfIhxrDXBHwsuP+7ZhJXHf78ERGEznKAPl46EKGcEginQVVHqQpWj0L440CDQuF6etRlG4sc1QQGHHG4HSxIQw==
X-Gm-Message-State: AOJu0Yyby+PZzI8H/2NoIDLkufVS2ZvPPz7ySN2DJtvznz/A69ClKqzc
	vHMQLK3BLrCowD+SJHadUClQRRZnLKeYbuc0A7IGsolRFiPn7WZy
X-Google-Smtp-Source: AGHT+IGPbL3kloib6bJVcIjBMlpvNVtKPoITCdyuDf8YF40K/FYBdPVY76rtuKKe6L7nkwo4YlZqRA==
X-Received: by 2002:a05:6871:5821:b0:22e:792e:4ac with SMTP id oj33-20020a056871582100b0022e792e04acmr3196043oac.43.1712156737728;
        Wed, 03 Apr 2024 08:05:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:520a:b0:22e:89b6:5033 with SMTP id
 ht10-20020a056871520a00b0022e89b65033ls466334oac.1.-pod-prod-02-us; Wed, 03
 Apr 2024 08:05:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVtDnTLAiLDVvnuFUC6GCJ5vx3pLtXyeixCjUHrEbUmvWSMQPgebrdWOkPD8xUepyNDQ26jlnV9iHRtgMpvORmG7/aOOGP/aUjqXA==
X-Received: by 2002:a05:6870:9728:b0:221:9227:e006 with SMTP id n40-20020a056870972800b002219227e006mr3168429oaq.47.1712156736700;
        Wed, 03 Apr 2024 08:05:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712156736; cv=none;
        d=google.com; s=arc-20160816;
        b=HozTpyrZhEXvc0/e5FH/93u9iXS607fcPv9QPAj07GcWktLk1U/gV6hPPjDWnYbC1u
         qE+K2sYVoHImytOn6a98TaJGmYhC9I9WLSrMJbSBTb0vv9uUS4nj7zPaMMQsxLhGCneG
         4pc2pg03UYAoSi+7MnwRHyVPHd0K5CP5XqYcyjPqiKXw3KssKCIcukuFHy5vYmcRS7me
         WMMg8cULoXC3kgJKKIhb2+mvxuwbYT60KYWsvT/C+tnIq+CQY9EA9Uvo+3sAqqCFP3Uy
         ZqgAlO8UR8sHG/w37u+QDfkOQ4fPded4W/Ba4CR0NzC4k6EIKXbRgyupzGuQ8XrBzYS6
         h1wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=UdTf2pSCOIaYn7Otxzx3C9HDo/HSUaFRAsJWaqzhTKw=;
        fh=QM13yX5cyx0gKVLH9qgXc292C0jk7N6nZCeRL8zZxhQ=;
        b=r+rhx+5VpKj8Eaz0EkAJtaQMeO6R8NGovxiUuTDVnkzQk2qGKQEVk9BXL28SZmBKH1
         E9akwE/Ir2EiGegrjv6dv7mOEj/T6yRpFsanckb0zoDS9z1p0yKcJ82oIGL+UZ/3uFQ8
         AY+e7BlbLvd+r6vxHKt0kHQMPICh4/YBh0+zOSzTQMFaFL2ny+n+39VCB8ylz6AVDYN6
         xFoQp59korCGNwk2EITMyhzMjQ6uFHneudfdK2+O6f53xUi9Vy9+At9noqzM7Ydw9zQ1
         18r2UyBP5lbdF7ZLjPY8oEXTQ1chor0U3Ijj8GKgpjOg0zXOuNAueizmntKWHWfPKylT
         /PiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bkJRxclQ;
       spf=pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id nx25-20020a056870be9900b0022e621de965si517786oab.1.2024.04.03.08.05.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 08:05:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of oleg@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-568-vxjWNBbPPnOwkeIjxQ0Jyw-1; Wed,
 03 Apr 2024 11:05:32 -0400
X-MC-Unique: vxjWNBbPPnOwkeIjxQ0Jyw-1
Received: from smtp.corp.redhat.com (int-mx02.intmail.prod.int.rdu2.redhat.com [10.11.54.2])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id B3B773822552;
	Wed,  3 Apr 2024 15:05:31 +0000 (UTC)
Received: from dhcp-27-174.brq.redhat.com (unknown [10.45.224.49])
	by smtp.corp.redhat.com (Postfix) with SMTP id B6D1C4073487;
	Wed,  3 Apr 2024 15:05:28 +0000 (UTC)
Received: by dhcp-27-174.brq.redhat.com (nbSMTP-1.00) for uid 1000
	oleg@redhat.com; Wed,  3 Apr 2024 17:04:07 +0200 (CEST)
Date: Wed, 3 Apr 2024 17:03:43 +0200
From: Oleg Nesterov <oleg@redhat.com>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: John Stultz <jstultz@google.com>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Edward Liaw <edliaw@google.com>,
	Carlos Llamas <cmllamas@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
Message-ID: <20240403150343.GC31764@redhat.com>
References: <20230316123028.2890338-1-elver@google.com>
 <CANDhNCqBGnAr_MSBhQxWo+-8YnPPggxoVL32zVrDB+NcoKXVPQ@mail.gmail.com>
 <87frw3dd7d.ffs@tglx>
 <CANDhNCqbJHTNcnBj=twHQqtLjXiGNeGJ8tsbPrhGFq4Qz53c5w@mail.gmail.com>
 <874jcid3f6.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <874jcid3f6.ffs@tglx>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.2
X-Original-Sender: oleg@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bkJRxclQ;
       spf=pass (google.com: domain of oleg@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=oleg@redhat.com;
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

On 04/03, Thomas Gleixner wrote:
>
> The test if fragile as hell as there is absolutely no guarantee that the
> signal target distribution is as expected. The expectation is based on a
> statistical assumption which does not really hold.

Agreed. I too never liked this test-case.

I forgot everything about this patch and test-case, I can't really read
your patch right now (sorry), so I am sure I missed something, but

>  static void *distribution_thread(void *arg)
>  {
> -	while (__atomic_load_n(&remain, __ATOMIC_RELAXED));
> -	return NULL;
> +	while (__atomic_load_n(&remain, __ATOMIC_RELAXED) && !done) {
> +		if (got_signal)
> +			usleep(10);
> +	}
> +
> +	return (void *)got_signal;
>  }

Why distribution_thread() can't simply exit if got_signal != 0 ?

See https://lore.kernel.org/all/20230128195641.GA14906@redhat.com/

Oleg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240403150343.GC31764%40redhat.com.
