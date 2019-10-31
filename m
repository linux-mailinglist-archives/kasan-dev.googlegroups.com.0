Return-Path: <kasan-dev+bncBDQ27FVWWUFRBNOW5LWQKGQE2K7H72I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C4F0AEAC99
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 10:36:54 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id x17sf4670943ill.7
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 02:36:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572514613; cv=pass;
        d=google.com; s=arc-20160816;
        b=J1dbD3d9/tnB4/JXbkEYlScQRvaeOGIwZVZmfBFqydf0flisvoSY1aTz6M+Snz9ZuP
         vbAdHAkfwohQTVo8j92Yp7NTtEv1CqsnbEWbUYKwLTuylQOArqSAAZKi3SVXALYEuCUc
         yq9AmeySqNhe8zpVVXgQX0+MSO9mWymbtUX+E8Ox8XfjnyFhJFr+zT4IfwmoSXge/l2q
         GKyiJ/Ma90mK7s6PykOTXRXLI9gO+cCCEEByNfUcl+KKkbuH46FrsKjyNPBG7BnHjRWv
         VDYc8rVW53dqSc/EMdF1YSQY8AvgfkeDQ7V82XPmNt5PTtLdGFFe0uZwPLN1nYEBBaaa
         8S6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=w1UOIfXBeH7TQzpFGFgpkeJ4k1gcjJXkpVN1zmY0kmM=;
        b=pe4F7SL9X5FDrn+cK4gvMPkER+svHAfeTO1RkIDjhT+pCjIUhRUr/c2sJdohJnmXdW
         i3WF3L4uJfamaLtmfwqnere56uObdxBeyKmmemPNFDepcKG4MniRnWBX+GB6Fr9U8zEQ
         P7rFw0DR0qpdqN3HREGOjs2D8Utj8qswtBOZi5VAMiJp69zc6ladhYnZYIA3Jr1ynFgo
         uEDDkSqFuKK2HezrrbgWMunCZagR8A2kGc7YbQvftrFshdc/Ee+SJGIOo4+k4N54honW
         +37DAcuYJ331lnDd8JaXS4wPrR+MjalOpJdz0YaBOx4aSFjYop8Bw0hKqwrEBnLebrWI
         LYJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=UQBU8pga;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w1UOIfXBeH7TQzpFGFgpkeJ4k1gcjJXkpVN1zmY0kmM=;
        b=tIImE7QuIfQ9UhhEDymtcKFHT0k0rXdSbbQPYgt+kzxXnNXIWHoZL1CcoQ2FWthtTT
         UB3T4nc+G7ApK48pmmRLQL7OYTiJsikUlcNOm7D9f8Xx1Wd00kf1Y1mJFONX+LrxxNRC
         3na6jt1vg641dMRPWKTzB245/0h0tsvWLS7s47+6eWxKCIMCmoIQpL6cCToJdJlv76Nf
         /mY5FBrOmXGxKgJ1pgkrNEv/0lRvQS2fpHuXtaQsudmnU1RgfmoqnooQKHTPTs3TspBt
         76K6A3ayEBQu08WPpqToBfStFlMGndIRztvxE8l5k7y8zpWtNso7DGonOgDGi72uzz5A
         MfqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w1UOIfXBeH7TQzpFGFgpkeJ4k1gcjJXkpVN1zmY0kmM=;
        b=S4uX7ezMGQUUCO1pg6zIagh9wjFYN7mhGOl/5grApqp5ZJHLpKVTcjD+l5hWSzNihE
         0mE85mvHngLy89NFBtiRnFPc61ionLW7w3A3V7VABVVO33I6RhGazrRAFPQMR6DxVphj
         qsD8/jIgDgtKWALBK5cQhSaHooLFd5U8rw489hd6Bqh3Jxp7zw/ZEZ9llzwPPuNFGyJV
         hEFdNi/BwBaAO9Xd2S1g+IQX70EKMrfxUyOSoO3R/EIx68E7uMQLPevg4H5kUbBSSFy7
         yE+LU2JlKxZTEdIhi/8b8XjYo7d4EZKNRGQy96koStUClvGUwyND9g9w1L4e1ZniMhnF
         APCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXQqO9gOqD7gTQeeQ6v93yLliMM35PfJGUTem+qzAGuPeHydmef
	m/W6E4FBrAzWZHQ75IATmE4=
X-Google-Smtp-Source: APXvYqzy1mLqv/CiSV0ax9XK79tHeenj/f6mhiy9pMG7sqmmmAzs0vYlFul13Twiymbu9bkrppcBHw==
X-Received: by 2002:a6b:c8cf:: with SMTP id y198mr3951432iof.213.1572514613757;
        Thu, 31 Oct 2019 02:36:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b7c5:: with SMTP id h188ls196149iof.9.gmail; Thu, 31 Oct
 2019 02:36:53 -0700 (PDT)
X-Received: by 2002:a6b:f408:: with SMTP id i8mr4203903iog.73.1572514613360;
        Thu, 31 Oct 2019 02:36:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572514613; cv=none;
        d=google.com; s=arc-20160816;
        b=qSL+XyQqfPOwG+Vj3isXYftF8gx5PGoWDyIRPICZgGwLFGSb0ca5d5kpbfzaJQkWMJ
         f1hc1asp9ouEQflytYOka1ezNTepw9mNllUowW5xrLA7Vab1BP5QAFefqHkIzbO1h6pz
         apV+E0blywJODirULIs3KMI0iJ6SI8uP9l1yBvatwA8PYGNMFLhtTBrCgvNiYFHWA7QW
         1ss3WSvwr8Y+uyg3XbA7O+0yM5oyQWvSaT//afo7vXYPBI7iGsRXhIxmxQLMzgcOYBIr
         RX5TR9JjWUPqBeqMGVVHj15GY7ZwmKXrgjNXojmfqZu7b9bwwYFnHh9VtAotpIhFUkVC
         JgZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=W3IvectI3U8q0HFF/2f4e8iwJrLi+nuiRQbnbTxHTY4=;
        b=Nxx2RTf4mTAQFB4lKQP7rFoQn52HfomuWie3Da4WTCivYyuwrFNTfbYcJMubEkAgr6
         D5ufrpQs6OJ8uN6RQET2t7KEIt2/HFcKdOrXJseRWIWgpM7/YlVLGqND6c3z49XXnufj
         PknJjfri3zfLh2jhZN8nBHBpv8zJATAtAvsAraESrhAeSe1eYcHXC2MqX1TrMs7+tIS7
         JO9KTehiM/69O1o+R79gF/t6/R/y23iMLRTBwvuXOG9pHD2kqoYLkxkV8OThp8s+0mLl
         ic+F4W9FwlG4bMuNiWJYthNqB+tK29tWV/TFkW3VQ7E6JVGMrdc+hvzcdeVQoeqeAnRc
         WeRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=UQBU8pga;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id x18si278344ill.2.2019.10.31.02.36.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Oct 2019 02:36:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id j22so3695718pgh.3
        for <kasan-dev@googlegroups.com>; Thu, 31 Oct 2019 02:36:53 -0700 (PDT)
X-Received: by 2002:a17:90a:c505:: with SMTP id k5mr5768175pjt.84.1572514612591;
        Thu, 31 Oct 2019 02:36:52 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-783a-2bb9-f7cb-7c3c.static.ipv6.internode.on.net. [2001:44b8:1113:6700:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id i16sm2708223pfa.184.2019.10.31.02.36.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2019 02:36:51 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Uladzislau Rezki <urezki@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v10 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20191030142951.GA24958@pc636>
References: <20191029042059.28541-1-dja@axtens.net> <20191029042059.28541-2-dja@axtens.net> <20191030142951.GA24958@pc636>
Date: Thu, 31 Oct 2019 20:36:48 +1100
Message-ID: <87k18lmf2n.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=UQBU8pga;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Uladzislau Rezki <urezki@gmail.com> writes:

> Hello, Daniel
>
>>  
>> @@ -1294,14 +1299,19 @@ static bool __purge_vmap_area_lazy(unsigned long start, unsigned long end)
>>  	spin_lock(&free_vmap_area_lock);
>>  	llist_for_each_entry_safe(va, n_va, valist, purge_list) {
>>  		unsigned long nr = (va->va_end - va->va_start) >> PAGE_SHIFT;
>> +		unsigned long orig_start = va->va_start;
>> +		unsigned long orig_end = va->va_end;
>>  
>>  		/*
>>  		 * Finally insert or merge lazily-freed area. It is
>>  		 * detached and there is no need to "unlink" it from
>>  		 * anything.
>>  		 */
>> -		merge_or_add_vmap_area(va,
>> -			&free_vmap_area_root, &free_vmap_area_list);
>> +		va = merge_or_add_vmap_area(va, &free_vmap_area_root,
>> +					    &free_vmap_area_list);
>> +
>> +		kasan_release_vmalloc(orig_start, orig_end,
>> +				      va->va_start, va->va_end);
>>  
> I have some questions here. I have not analyzed kasan_releace_vmalloc()
> logic in detail, sorry for that if i miss something. __purge_vmap_area_lazy()
> deals with big address space, so not only vmalloc addresses it frees here,
> basically it can be any, starting from 1 until ULONG_MAX, whereas vmalloc
> space spans from VMALLOC_START - VMALLOC_END:
>
> 1) Should it be checked that vmalloc only address is freed or you handle
> it somewhere else?
>
> if (is_vmalloc_addr(va->va_start))
>     kasan_release_vmalloc(...)

So in kasan_release_vmalloc we only free the region covered by the
shadow of orig_start to orig_end, and possibly 1 page to either side. So
it will never attempt to free an enormous area. And it will also do
nothing if called for a region where there is no shadow backin
installed.

Having said that, there should be a test on orig_start, and I've added
that in v11 - good catch.

> 2) Have you run any bencmarking just to see how much overhead it adds?
> I am asking, because probably it make sense to add those figures to the
> backlog(commit message). For example you can run:
>
> <snip>
> sudo ./test_vmalloc.sh performance
> and
> sudo ./test_vmalloc.sh sequential_test_order=1
> <snip>

I have now done that:

Testing with test_vmalloc.sh on an x86 VM with 2 vCPUs shows that:

 - Turning on KASAN, inline instrumentation, without this feature, introuduces
   a 4.1x-4.2x slowdown in vmalloc operations.

 - Turning this on introduces the following slowdowns over KASAN:
     * ~1.76x slower single-threaded (test_vmalloc.sh performance)
     * ~2.18x slower when both cpus are performing operations
       simultaneously (test_vmalloc.sh sequential_test_order=1)

This is unfortunate but given that this is a debug feature only, not
the end of the world.

The full figures are:


Performance

                              No KASAN      KASAN original x baseline  KASAN vmalloc x baseline    x KASAN

fix_size_alloc_test            1697913            14229459       8.38       22981983      13.54       1.62
full_fit_alloc_test            1841601            15152633       8.23       17902922       9.72       1.18
long_busy_list_alloc_test     17874082            58856758       3.29      103925371       5.81       1.77
random_size_alloc_test         9356047            29544085       3.16       57871338       6.19       1.96
fix_align_alloc_test           3188968            19821620       6.22       37979436      11.91       1.92
random_size_align_alloc_te     3033507            17584339       5.80       32588942      10.74       1.85
align_shift_alloc_test             325                1154       3.55           7263      22.35       6.29
pcpu_alloc_test                 231952              278181       1.20         318977       1.38       1.15
Total Cycles              235852824254        985040965542       4.18  1733258779416       7.35       1.76

Sequential, 2 cpus

                              No KASAN      KASAN original x baseline  KASAN vmalloc x baseline    x KASAN

fix_size_alloc_test            2505806            17989253       7.18       39651038      15.82       2.20
full_fit_alloc_test            3579676            18829862       5.26       21142645       5.91       1.12
long_busy_list_alloc_test     21594983            74766736       3.46      140701363       6.52       1.88
random_size_alloc_test        10884695            34282077       3.15       91945108       8.45       2.68
fix_align_alloc_test           4133226            26304745       6.36       76163270      18.43       2.90
random_size_align_alloc_te     4261175            22927883       5.38       55236058      12.96       2.41
align_shift_alloc_test             948                4827       5.09           4144       4.37       0.86
pcpu_alloc_test                 371789              307654       0.83         374412       1.01       1.22
Total Cycles               99965417402        412710461642       4.13   897968646378       8.98       2.18
fix_size_alloc_test            2502718            17921542       7.16       39893515      15.94       2.23
full_fit_alloc_test            3547996            18675007       5.26       21330495       6.01       1.14
long_busy_list_alloc_test     21522579            74610739       3.47      139822907       6.50       1.87
random_size_alloc_test        10881507            34317349       3.15       91110531       8.37       2.65
fix_align_alloc_test           4119755            26180887       6.35       75818927      18.40       2.90
random_size_align_alloc_te     4297708            23058344       5.37       55969004      13.02       2.43
align_shift_alloc_test             956                5574       5.83           4591       4.80       0.82
pcpu_alloc_test                 306340              347014       1.13         571289       1.86       1.65
Total Cycles               99642832084        412084074628       4.14   896497227762       9.00       2.18


Regards,
Daniel

> Thanks!
>
> --
> Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87k18lmf2n.fsf%40dja-thinkpad.axtens.net.
