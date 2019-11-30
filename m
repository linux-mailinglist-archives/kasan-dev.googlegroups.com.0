Return-Path: <kasan-dev+bncBDK7LR5URMGRBYPERHXQKGQE2WHUHJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 532E610DDCC
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 14:45:06 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id d8sf13273565wrq.12
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Nov 2019 05:45:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575121506; cv=pass;
        d=google.com; s=arc-20160816;
        b=f0BaZ2osxGH0T2fN91aUQZ6jyRAYbyxggxAesoV1VaWGBJDZ4rMvMLzcYm3KmxLjKm
         JJx9X4bN7PItI283bmd++/PQU/vtcE1tM4xmWVOT3g63XKnOkde+KDTDCwJOmJyUFu7n
         TTU7WfGcbxDVeN5NqdtUKlHAcgOXSUmTBYABtvmKPkaWXLs48YWqdDkwTM+WfSbvqCoM
         evXh3ATyrirTRbAzRPTpJVFOU+a/q7Is9b6S1CVXmZ+pqmitCJlQ1sHUR7LoUNneMufT
         HRoWO8uo8uCdRT5HFLCc7HWcPNz3FtAAEaz/M8N2ZATnX1YuDX1FPn5Sd/64CDiyuOqO
         6ttA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:sender:dkim-signature:dkim-signature;
        bh=AXaeTsXskcBIhPhG6NH3PWA1T63bTB5gVtQQ+zXJ4qc=;
        b=LDfocsrYD+SK11Q3VzDX2Byd42R/PvAOn2r4cEw2cY27fD/H8Fh4CWKQIaHD/nzn0G
         pAbM4Vc94nUBUo98FC6E/AvH07Ea+Nzsi7yYuNl8AipCq0PMBLnHMVOihgXyp6Hix2nU
         wErQChYf4oibd5uKq3dXTUg+GY0WodiuZSW4ER8jJwf7HPG7zf6dOUvN5tV591ze14Ll
         6eWHQlY9yKejNUyOFXhXiIu8AJHNDOCtzJRq4TPKcmMSk0L2M77soMOyBKPrHto2Ui42
         +XiMrco/dhGypjRRXelgo2TFqiNDcJLu+4yxZf/Rjv9kEhIYBQ6zO72SDfzIcU/MuEoQ
         usww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=LBo+ojo5;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AXaeTsXskcBIhPhG6NH3PWA1T63bTB5gVtQQ+zXJ4qc=;
        b=K7+IqC28D+td2fHOo1OwXNHzGfXtTVQZieogVorytTae17WtgSCQx2zcwuA6GWaDJS
         nMBUNZuCIZQ9gZ67Qn5lHdQH/+hRCeeGiwGpTNOno80jbwXwsJIM1UIuJyIUpuZTw25V
         EgKjOVZucvwczITgv8PJ7Xsec+lmuvEfV36NhCsn+H6R1skNQvH/j6sGgCRaxosUNh0p
         nLefBQQdHskxDoq3CvFLQCkHp86RJHPuqMPBn3ND+Jaby6iIJYqpIkjMFTsNEDySBq4D
         NN1v0aa3XMVF84zOy20qixOIXahWaj/fVaL9KzUa/obMdaGGjOWrwBMZ7oqhM6GeUGEU
         0RhQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AXaeTsXskcBIhPhG6NH3PWA1T63bTB5gVtQQ+zXJ4qc=;
        b=tokRzAooHDGkvc/Meo7cwJh0EQs1hMsaNOocsXn47iWpc/fG+AcxWjwKOMUUkPzk8F
         GCiJGMDmqe2rUMMZ8MZTDjDI5nqBFRfjpZwEqOoKw+nBOGFSmVCsOo7r6mHLlJDESAOb
         mKSxpOPZf0JYSf1wVg8fxfkqWZvxHi/n1YU2v3Rz4JWgstauTfrOolK0bbU0ktDjnzRK
         1c+bXjlq0pu3K/Q/ArxdtUJeGap43qhEJgdFk9szjNviNOwJJzWlQFTkprw0PpfPSINs
         K2RUIX4uw88Tbe+ukpdaDj5kHeu1FEM9Hdr+HK1+3uZxVL97+i+e/5FpFQZXcHeeZ2iB
         HmBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AXaeTsXskcBIhPhG6NH3PWA1T63bTB5gVtQQ+zXJ4qc=;
        b=TYGhOW3/E3+HjRvpKWwrJdctnpfjajX+vU8l2M1EMq9+LlSBHfjJdXXS96odtJsR2C
         QCgHO0H4kwYH52LGc9j6OUA5PnHHZdcmGR14WHLbyoepVocDJUMnXyFrqb0KjXOnCswW
         MEnncwr0ocDcRKlhA3KJLg/2Hpy4HkUt2Y4TwsLjUS1ti6CImQ30As7fK3C8EBXWq28m
         GcFGFs46zYfgMKjpmlyAvs27uWjbDbbxPcyYWHCn+e3mtL0ydoyr3a1VYZUbm3UvsHGy
         oY743xBQVSYoCTf3Hlkn3gjQFW7GDxfy6a1HSVfRAVK4dgLnAA3sfo427jmdF33qHkIu
         UtkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWBMyyjztNic46xbbhjRCs8/7/RJFQiUq7gVv3uGuYMqB472qhJ
	06jmLY0dg/Lj7Ts85zjWlHU=
X-Google-Smtp-Source: APXvYqz7EyX8WVzOufKL/IP8pljA1YY9qwLDVfEm7u+pbHuonleAiDeJAAZxJ3LJSRlghzpJ+y7KBQ==
X-Received: by 2002:a1c:ed05:: with SMTP id l5mr20894638wmh.161.1575121505789;
        Sat, 30 Nov 2019 05:45:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:55cd:: with SMTP id i13ls545316wrw.0.gmail; Sat, 30 Nov
 2019 05:45:05 -0800 (PST)
X-Received: by 2002:adf:9185:: with SMTP id 5mr62123308wri.389.1575121505299;
        Sat, 30 Nov 2019 05:45:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575121505; cv=none;
        d=google.com; s=arc-20160816;
        b=fz5kIzZNqbe+ZobNt2PT10BatdrFyL73OkRYlohmloH8Puwlins6qcPoMBGXpL0SAZ
         15qs+FWNxxwArHyoQys8/KxEv0xHRVcby3uvECS8FziPasqMcFgLSoOvTh4GQ1APyG9q
         gTI8zdxy/oLtZKO/Ohv8YG79Al5b9TZ1oaqN9GrbrgnvkSMDUUron5TPNWPggzwiaSB6
         UobuUb353dcrwEg68GpIh2dOySdAr/G3D9f2jH9Em8i8arnyvfKSjQJeaR6n5k4k3ObY
         K1+qqU/wwN+NvXWbabqdbrMQNZWYXbQmIrqGXqeiDKaTx+MqU6F1RG3TNFvX/zzGVkvT
         wl5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:date:from:dkim-signature;
        bh=EX4Yje1/DqSKTDoH2ZOXvXZz8HHNkGdgnUsG/hOKdBw=;
        b=odFsX4APKt48o2RQDqReUU4swyF0+91B7ekrKZlMZmdp0QwqJaQL35xXTbFomhLyGw
         72z2JgbYFtjOCyYTL8Z7AKKbjTHtynR2PUDBesjxR+BwEgC5T7pUYiRqH+s7l6YZUtkD
         6JMyxKrSLiubqzS4yZpeXgrjpgrsW9+uO2YMHBciDTzNBWxeEndbzUbgN8UnBj5wruV6
         GkCj15WBBm2vgVrzxwuoZU5W4TUWwCKcb4BlNIDv/5MgbN47eigYfEzmrseRQr8iuoqD
         MQ1wQkEWpU5AE0n6c/M2o6w3ALuALmHOJjspYa6D5aRYIhAgMWVhgkVSax0DL2luv2w6
         Up1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=LBo+ojo5;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id 12si974576wmj.1.2019.11.30.05.45.05
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 Nov 2019 05:45:05 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id l14so24548695lfh.10;
        Sat, 30 Nov 2019 05:45:05 -0800 (PST)
X-Received: by 2002:ac2:5c4a:: with SMTP id s10mr11141071lfp.88.1575121504733;
        Sat, 30 Nov 2019 05:45:04 -0800 (PST)
Received: from pc636 (h5ef52e31.seluork.dyn.perspektivbredband.net. [94.245.46.49])
        by smtp.gmail.com with ESMTPSA id a18sm11758745ljp.33.2019.11.30.05.45.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 30 Nov 2019 05:45:03 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Sat, 30 Nov 2019 14:44:55 +0100
To: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	syzbot <syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com>,
	Daniel Axtens <dja@axtens.net>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Subject: Re: BUG: sleeping function called from invalid context in
 __alloc_pages_nodemask
Message-ID: <20191130134455.GA27399@pc636>
References: <000000000000c280ba05988b6242@google.com>
 <CACT4Y+Z_E8tNtt5y4r_Sp+dWDjxundr4vor9DYxDr8FNj5U90A@mail.gmail.com>
 <77abfacd-cfd0-5a8d-4af7-e5847fb4e03a@I-love.SAKURA.ne.jp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <77abfacd-cfd0-5a8d-4af7-e5847fb4e03a@I-love.SAKURA.ne.jp>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=LBo+ojo5;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::143 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sat, Nov 30, 2019 at 09:48:34PM +0900, Tetsuo Handa wrote:
> On 2019/11/30 16:57, Dmitry Vyukov wrote:
> > On Sat, Nov 30, 2019 at 8:35 AM syzbot
> > <syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com> wrote:
> >>
> >> Hello,
> >>
> >> syzbot found the following crash on:
> >>
> >> HEAD commit:    419593da Add linux-next specific files for 20191129
> >> git tree:       linux-next
> >> console output: https://syzkaller.appspot.com/x/log.txt?x=12cc369ce00000
> >> kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
> >> dashboard link: https://syzkaller.appspot.com/bug?extid=4925d60532bf4c399608
> >> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> >>
> >> Unfortunately, I don't have any reproducer for this crash yet.
> >>
> >> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> >> Reported-by: syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com
> > 
> > +Daniel, kasan-dev
> > This is presumably from the new CONFIG_KASAN_VMALLOC
> 
> Well, this is because
> 
> commit d005e4cdb2307f63b5ce5cb359964c5a72d95790
> Author: Uladzislau Rezki (Sony) <urezki@gmail.com>
> Date:   Tue Nov 19 11:45:23 2019 +1100
> 
>     mm/vmalloc: rework vmap_area_lock
> 
> @@ -3363,29 +3369,38 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>                 va = vas[area];
>                 va->va_start = start;
>                 va->va_end = start + size;
> -
> -               insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
>         }
> 
> -       spin_unlock(&vmap_area_lock);
> +       spin_unlock(&free_vmap_area_lock);
> 
>         /* insert all vm's */
> -       for (area = 0; area < nr_vms; area++)
> -               setup_vmalloc_vm(vms[area], vas[area], VM_ALLOC,
> +       spin_lock(&vmap_area_lock);
> +       for (area = 0; area < nr_vms; area++) {
> +               insert_vmap_area(vas[area], &vmap_area_root, &vmap_area_list);
> +
> +               setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
>                                  pcpu_get_vm_areas);
> +       }
> +       spin_unlock(&vmap_area_lock);
> 
>         kfree(vas);
>         return vms;
> 
> made the iteration atomic context while
> 
> commit 1800fa0a084c60a600be0cc43fc657ba5609fdda
> Author: Daniel Axtens <dja@axtens.net>
> Date:   Tue Nov 19 11:45:23 2019 +1100
> 
>     kasan: support backing vmalloc space with real shadow memory
> 
> @@ -3380,6 +3414,9 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
> 
>                 setup_vmalloc_vm_locked(vms[area], vas[area], VM_ALLOC,
>                                  pcpu_get_vm_areas);
> +
> +               /* assume success here */
> +               kasan_populate_vmalloc(sizes[area], vms[area]);
>         }
>         spin_unlock(&vmap_area_lock);
> 
> tried to do sleeping allocation inside the iteration.
There was a patch that fixes an attempt of "sleeping allocation" under
the spinlock from Daniel:

https://lkml.org/lkml/2019/11/20/22

--
Vlad Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191130134455.GA27399%40pc636.
