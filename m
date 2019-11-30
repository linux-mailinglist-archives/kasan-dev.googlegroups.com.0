Return-Path: <kasan-dev+bncBCTPB5GO2YNBBKWKRHXQKGQEFFMM7TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B00010DDA6
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 13:48:44 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id s131sf14480560pfs.21
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 04:48:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575118123; cv=pass;
        d=google.com; s=arc-20160816;
        b=DO3RCqcygvZQzntbRdvSJ4HcLS8/xOwt90pw12MNi8+/WzWiuiHeDrmh4UZIUpO1BR
         6mFFSMT/3aZ9N1H78Xp2FT+tkel5TFasyKJOLEYZl7Zj++YuIq/XOyEcxOWeVuYlNqT7
         tKv/asd2SZNrKAl3SeHbrzViDgl2gGllKVm4odTHX6OR7h8ltIFuqDiGcx9hcHjgx/oA
         WYv5voqD2BbvLDjNQTypjYTsbbpUtxrqh9F7Khx3kq9usrvNnvyVyNpN0kmlOpYhIAb8
         EMF8XS2Fees4vWl/T0UZqYJ5tkY71u0RH/Bvoj0hEncOJxzntaIIj+XWkEdLz7gw1fwx
         j+9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=GdNvjodUjtl2oq6hdS7PQSMktyfmPxA3nZMIgVkZi8M=;
        b=eEg2y4s7uCLkap6xhq8Xp3XKBqqAaBmqKXT+KDBT+RLyQRTiw/RzpKBVwaxMdY4D3S
         cu4C1De8GdA3LLHTiZlSfksIBXcd22LhUoqSzaw9ibxayfXHeNt/rJ4m8tAGelfo8/zR
         Xo0ej4HMTDQvGSsSRdzbyNotMm4d6VW68JTrbIIoYkkDJTAFu+tYEV9Ceohi2rMikt5/
         eO9bM5zuws7PML7Vi1beWOOAFL4BzpL146KuoQgdbxFn/dx50qkRj5e2GNJc2PcdmFVH
         R2CzuQF699nnGGuBuQ8K7kQpTT896E64H49Ir3RmSq3tYL/arTWl37Mac0MowdASPj+S
         rOLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GdNvjodUjtl2oq6hdS7PQSMktyfmPxA3nZMIgVkZi8M=;
        b=hEPm3ddRAX4dtDXJ0xRKfbUsUFwH2utsv0ib6wLjAKZIyJCgiDT3r+2UCWUntDkYuO
         0tkitVLdtMCuCXtPWGXpKVWIQ7EtpAVOYbjz5U9hLn+z7R96UZ1mFRrjtXGuc6k5BSRh
         7vh4xlbx+l8Zvp6ozw9LUUue/u2oAt6RQCk6gJvi8Toi1DaA8E/77EqFUC7x7CO44IWM
         x7ALc6FTWPeB+AnnpkL/OVK3AQepwP9SF9Kvv0/a7vVJKENPDBVQjsyNohoHxlmMj7Je
         0eL3ezFCnEMzlEkp6cGoTRDZ/6V86zTJjJT1FGfrHXBkLc99cHRPR4okegmNkazhqzJx
         u7ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GdNvjodUjtl2oq6hdS7PQSMktyfmPxA3nZMIgVkZi8M=;
        b=GkAplPEMg/kv9KvrioW+XuNEwubI1/KY4WVL/WC1yXf4+wEF/AuTFINFZTCRFIXmOy
         snH7+CpZ0TQdmHx8378zjZwEI/W9/y1AXe+AUUNQngvuRneKUoisSqm6AOyV9dBAYuqR
         5me/+CJfMWKtg/Be2og4eEisBW6V0EIByzfw+C1FV9Wz2NZ92HQ5IloTQ0q8sWuVythd
         vxBBfvsQEuN5JViRenTmf4tz8HgoCpuX7+M2QbL0Q8M2qim7k3fgPaqRITvPeISEXqsn
         W/E2zdLdzP5Z5wwziLZkQy//5iyVpl9k6hgbVAF5JHeeeH8R3oi7yH8aV2EiVnpJJb9t
         MJIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVNqhwcP2ezLoM2vBBRVweq8ME7Oo6azcyoGjEtV/vfUqkbL17u
	Ho5N1ha7aoZS+rhTjUxuO64=
X-Google-Smtp-Source: APXvYqyq0HFY49ueHVAVhbGvkFL09OW5PStu5PfmsOUb0qKR/yFFECXo9VdB+O1/AmLwo9O9aRK++A==
X-Received: by 2002:a63:2808:: with SMTP id o8mr1636596pgo.39.1575118122833;
        Sat, 30 Nov 2019 04:48:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad06:: with SMTP id r6ls2772310pjq.3.canary-gmail;
 Sat, 30 Nov 2019 04:48:42 -0800 (PST)
X-Received: by 2002:a17:902:54f:: with SMTP id 73mr19529210plf.213.1575118122353;
        Sat, 30 Nov 2019 04:48:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575118122; cv=none;
        d=google.com; s=arc-20160816;
        b=bOjohz6Oxam7e/SUxHpy4YwStvVq1P3tb/O8YRKZiLzlUm3TYSbtN9ZgMOX9jv0ALb
         m24z3/tjPiWyR3XObAb1WhEU+yxIxEXgaumeIWWU0PVFJRGIX0CnfLp5cX9SUW/FHPLa
         yikAuHgTAbmuq4HKlmuBGlaVlUGYSitgkHqSpnRdaG6Mz7Vi0kvHdR2OsVyVPMPijQrD
         lKB4GDXh8QmeYIyCPto8eA5tbdNOFfWv8sjoLRCUqDB+KbHj6j8Js3x9siv5suzUmfMn
         F5GpqLROdeCd6Z4KyJ90TsQ9/ajoatZq7QtfwIJdJzL508mBcsGa/Gvk4FjjStCdV1zt
         W5pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=rLAJYYFD3WV/p71yWNlfqCyKuY2KS38QD1Dtz7p3djA=;
        b=g6vNHgXyGrXs5x5O9062FMVKSRyTVKROQWC/oGQPsh+ZZcPlprNjNg3CuLNsX6cuKd
         Rqe4+rz1mJkujqesmWELTYo1YtNtLdXLlrrccSoY7TzVzzuYy7r3o/t9/IQd/NqmFTMW
         JMdBX6ruRC/AgfW9CNRgPEtedyqlQ51M2cHfCW4UFSrQW4OWK0rS5HzTEJjM0stA63TD
         hx8JW0zPXwRiuxVa18nB3Rx3CEl0MobLMJTWDvqL4CSxq4eKGzLi9oxgXCpWxc6b2jfj
         1VZaFpPuDGRVZiSSYKR2YJXB9Qt3UiuJvdDutOZZq8Ii21e4yQFwW1KLgiX0pqnOLM47
         /tag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id w4si677994pjr.1.2019.11.30.04.48.41
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 30 Nov 2019 04:48:42 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav106.sakura.ne.jp (fsav106.sakura.ne.jp [27.133.134.233])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id xAUCmYxe079069;
	Sat, 30 Nov 2019 21:48:34 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav106.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav106.sakura.ne.jp);
 Sat, 30 Nov 2019 21:48:34 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav106.sakura.ne.jp)
Received: from [192.168.1.9] (softbank126040062084.bbtec.net [126.40.62.84])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id xAUCmXcG079065
	(version=TLSv1.2 cipher=AES256-SHA bits=256 verify=NO);
	Sat, 30 Nov 2019 21:48:34 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Subject: Re: BUG: sleeping function called from invalid context in
 __alloc_pages_nodemask
To: Dmitry Vyukov <dvyukov@google.com>,
        syzbot <syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com>,
        Daniel Axtens <dja@axtens.net>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
        syzkaller-bugs <syzkaller-bugs@googlegroups.com>
References: <000000000000c280ba05988b6242@google.com>
 <CACT4Y+Z_E8tNtt5y4r_Sp+dWDjxundr4vor9DYxDr8FNj5U90A@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Message-ID: <77abfacd-cfd0-5a8d-4af7-e5847fb4e03a@I-love.SAKURA.ne.jp>
Date: Sat, 30 Nov 2019 21:48:34 +0900
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+Z_E8tNtt5y4r_Sp+dWDjxundr4vor9DYxDr8FNj5U90A@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp
 designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2019/11/30 16:57, Dmitry Vyukov wrote:
> On Sat, Nov 30, 2019 at 8:35 AM syzbot
> <syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com> wrote:
>>
>> Hello,
>>
>> syzbot found the following crash on:
>>
>> HEAD commit:    419593da Add linux-next specific files for 20191129
>> git tree:       linux-next
>> console output: https://syzkaller.appspot.com/x/log.txt?x=12cc369ce00000
>> kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
>> dashboard link: https://syzkaller.appspot.com/bug?extid=4925d60532bf4c399608
>> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>>
>> Unfortunately, I don't have any reproducer for this crash yet.
>>
>> IMPORTANT: if you fix the bug, please add the following tag to the commit:
>> Reported-by: syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com
> 
> +Daniel, kasan-dev
> This is presumably from the new CONFIG_KASAN_VMALLOC

Well, this is because

commit d005e4cdb2307f63b5ce5cb359964c5a72d95790
Author: Uladzislau Rezki (Sony) <urezki@gmail.com>
Date:   Tue Nov 19 11:45:23 2019 +1100

    mm/vmalloc: rework vmap_area_lock

@@ -3363,29 +3369,38 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
                va = vas[area];
                va->va_start = start;
                va->va_end = start + size;
-
-               insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
        }

-       spin_unlock(&vmap_area_lock);
+       spin_unlock(&free_vmap_area_lock);

        /* insert all vm's */
-       for (area = 0; area < nr_vms; area++)
-               setup_vmalloc_vm(vms[area], vas[area], VM_ALLOC,
+       spin_lock(&vmap_area_lock);
+       for (area = 0; area < nr_vms; area++) {
+               insert_vmap_area(vas[area], &vmap_area_root, &vmap_area_list);
+
+               setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
                                 pcpu_get_vm_areas);
+       }
+       spin_unlock(&vmap_area_lock);

        kfree(vas);
        return vms;

made the iteration atomic context while

commit 1800fa0a084c60a600be0cc43fc657ba5609fdda
Author: Daniel Axtens <dja@axtens.net>
Date:   Tue Nov 19 11:45:23 2019 +1100

    kasan: support backing vmalloc space with real shadow memory

@@ -3380,6 +3414,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,

                setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
                                 pcpu_get_vm_areas);
+
+               /* assume success here */
+               kasan_populate_vmalloc(sizes[area], vms[area]);
        }
        spin_unlock(&vmap_area_lock);

tried to do sleeping allocation inside the iteration.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/77abfacd-cfd0-5a8d-4af7-e5847fb4e03a%40I-love.SAKURA.ne.jp.
