Return-Path: <kasan-dev+bncBCAP7WGUVIKBBC5UR22AMGQEPNRYCMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B73691EEC5
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2024 08:11:25 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5c227e4d99bsf2424136eaf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jul 2024 23:11:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719900684; cv=pass;
        d=google.com; s=arc-20160816;
        b=H4rVF5BY/qtloyIWHRsU9YEXRqoJXejHb/kYJux2NnoenRG7jb8vftoRoZdkpgTRD8
         n90/DTD2Tx4MXSjfVlzpWdTcz3WLtAuNTtxOM4U59POMGGXFNysqAOz66p1cBtnI9mVm
         XfavpLTPwItQsto+F0jn91YoWj6wssvHoYgKwYjNd91V7/l69jH8RH2EYirrRid4Vd3s
         gu2zF+as3P8WK0pU+PR3bs5MYq9v6NRqnwh80exUvqh24sInnukjfSZ30FJjasHqlm/9
         /RULkVLc6inDB8ONqf4GmMLNTcX+Kj5gB4CmHqWP8vIgCnj8ro1CrNKhasE4rO/wAOHW
         yqRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=NMO1EC7JOVQjCwfCPLfh86He01pqHQZ4I7jlSQsxxv0=;
        fh=xcz7DRHWhdomTzKMvYoUk9OfmI+i3SJFoGh29cZGJd0=;
        b=nfUZTC9G4ZCemixe1dnSm62p3M1NEevmKH4BywzExHpoOO8qBFhD94qSZQ5CLIPOhI
         xc/BVAgWqlSMbLjiYkSBeQuWDAcC/11D39oPMbkEHFY8EKYyeBQJ7ixB1S/skKlWTUPD
         bQwCsLSi3JVb9zUeOD9poYsxPE8greThDhrQjFhcckYNl4uu62V0ABS2YLEU71DoHqap
         gIzCjcG0pnZonmPtwWVRPIh8L4BUsIIkPq87m3M2vuZHtcMzrt5MuSiZzlh8DzXFSUPM
         DoOwRC1l9e+idAWRpxFG8p+7dt6x9/DZk/Fl3KdLatjEiiLYDjRrv0qOm24zMIcAQ3xK
         dbqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719900684; x=1720505484; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NMO1EC7JOVQjCwfCPLfh86He01pqHQZ4I7jlSQsxxv0=;
        b=YJ+Xmzbf/SVUpI0VvoNWxNFMNVcx22nTDOwTXu+GiErxV9YCmkrj0YGPY9aQRiaU4M
         0+OYyk/3a4NOeWVBU3KNCNrpUi9EeRhSp+1At7LJC8WIoMakqxJUZITMuBILXXQDE5lu
         qhacoSgzJ5ebgKmgzUKYi6KXOF9xN2jP/AkRiZ1taz7gm7IgX2ZBDcYMxvTgLcqoQWfv
         Hp47+biiGs5I8lPBK5t1AgNcuVFtyX7dbS44cMlUazAexQebotBXL/81mNykdjEUbhw7
         YfhnacDQCuIOh7BcB3zYj5Fn/rsdNKjzCLqLSa52n9v2gOl+OQ9XRV/e1NfVJ3udgAqn
         CNbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719900684; x=1720505484;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NMO1EC7JOVQjCwfCPLfh86He01pqHQZ4I7jlSQsxxv0=;
        b=AVght0m/w0zFQYdYjHSMnEwymZ8bp5w8AXCmaZ7XqorwoIloBQRAG6lVTLq0M5a2l8
         gK2G7Kc7m+YUKXRxEgxzEjc9L7Eugf4kln9fx/cOVfRccC0JHNrIs5WmjGyV7Q+lUwTg
         rY6WDZLIID+sDF7nYDXMFrb5o5bYwBDvnKBL2nbVGFYXxTvrcDopNARs21QX9VQKye2U
         PsSUuvMGA7MlvtuiIUDNp51jivhhHSv708nCoHgC9e9KWjhOULU5Sv2c4ggiVAt016ga
         4DpediIjx+9gYh3QLvwqljxbha21XaY9RxdZdTHR44gYw7AOzQdsmWvZvuFa1b/a4oAV
         /RJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhfNTRU5K0apMzkinUMlE65YoTmI/nJboiMUDlwscBZcXo6eXagcGx2RG53oHyX6yi1e8wNfPOsqDmO3oSAigsyW6eYTw85w==
X-Gm-Message-State: AOJu0YxeRktqmYmT3CmsoScQKNYPiUMJSMEvfAH2fTDDCtpgmUIQ1gho
	JEAdvpTYfY9OU6BvWL2Sxl5kI9QbEouZyooWzzBjm9I2hjXIXzPK
X-Google-Smtp-Source: AGHT+IH8Bk0Mlx6gyBuoJrrgko6ktF+/UFPJ9Pc2oPd46p4kPkLjjaIKzwNW8ihWuf20KAdx0zpPJg==
X-Received: by 2002:a4a:5550:0:b0:5bb:1310:5f37 with SMTP id 006d021491bc7-5c438e21152mr6226438eaf.3.1719900684160;
        Mon, 01 Jul 2024 23:11:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ae0a:0:b0:5bd:97df:20ff with SMTP id 006d021491bc7-5c4163dc1aals2615768eaf.0.-pod-prod-06-us;
 Mon, 01 Jul 2024 23:11:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgAo1Vo8D12gqfBMJ0b+3mLPaVsDtwKdRZVVfyTTgTUFIzIOj5gcYHv7bCArB00eL1wMjPQI22Vfz5hm0r4J9YCNqs9VVbV2UyRw==
X-Received: by 2002:a05:6808:159b:b0:3d2:1da4:af63 with SMTP id 5614622812f47-3d6b4de260amr7039039b6e.45.1719900683067;
        Mon, 01 Jul 2024 23:11:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719900683; cv=none;
        d=google.com; s=arc-20160816;
        b=PHILVhgzu8J8A0UQuPXOtNU+sEu6C3PxWuCZTAyhDM8V6B5MhJ8Lth4fM5sYm/mQB8
         /i9RpCQE3rSu3DfkbOignXru1Uk5my4kmNUvTLmVinZlzWXG4j3MzIBxl13gxkXMXsdY
         tdbK4qjKQiy0PJ3WABcmNlVyOaGXZE8h9wp1QCfByCc+QlD45cnr0DQKPzJQ0QwLsy/5
         77x6ZIh3UIPwGbnbpeTh+BcMdDWo1uvF/2NLFkLti53gjLf4dKVcNR5x2Jms/CTP1qY8
         5xcXm4BEmYzLqCm4BO59k+NyHYsdTP6XpazOqb9iQeqxqToB397Mpaj/Rr5pIZqYgrVW
         QbyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=aipXP6U0it2yCLNzIud9XOFvsxpQnzfISMQfLdpsa8M=;
        fh=/X6ch4A1P7mqFjFzh04ZrXpxVqEtT2Yo7A5UxE4IwbE=;
        b=m8EFRCcwjE3N5WEdFZMX0c0tgpL0K+GVIx4iAGqzXbCRIp0mYh5ay274OjCJDMWAhj
         jksuVyNjt9AMhglE1tPPOLwo21BppIwoJt4ZnE1nKk2vZhAqw9VC6GILGzLI5xDYzRG8
         ZEIJM9dSz7CEh2E9P+eQbDcIXSYrzM+2Blk1Qy1S5HeieYsCHHhM2YchehGswS0FtKWd
         9ixg2KfqXilrfJl9eKYaBJ+TR44IRDEYW7MVU3o9GDDSlIOHHT44lsB0qceQP1vORQzi
         4qhMS3uvolozyksfGr3NZ/odNSASQpIJ1iiAVCMODiToFqZJ5NHQrkbj7gwlnHIEmXsT
         3oPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70803ed2963si373191b3a.4.2024.07.01.23.11.22
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 01 Jul 2024 23:11:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav315.sakura.ne.jp (fsav315.sakura.ne.jp [153.120.85.146])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 4626BDsl058061;
	Tue, 2 Jul 2024 15:11:13 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav315.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav315.sakura.ne.jp);
 Tue, 02 Jul 2024 15:11:13 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav315.sakura.ne.jp)
Received: from [192.168.1.6] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 4626BCmT058057
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Tue, 2 Jul 2024 15:11:12 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <ec7411af-01ac-4ebd-99ad-98019ff355bf@I-love.SAKURA.ne.jp>
Date: Tue, 2 Jul 2024 15:11:12 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [kernel?] KASAN: stack-out-of-bounds Read in __show_regs
 (2)
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: syzbot <syzbot+e9be5674af5e3a0b9ecc@syzkaller.appspotmail.com>,
        linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com,
        kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>,
        bp@alien8.de, dave.hansen@linux.intel.com, hpa@zytor.com,
        mingo@redhat.com, tglx@linutronix.de, x86@kernel.org
References: <000000000000a8c856061ae85e20@google.com>
 <82cf2f25-fd3b-40a2-8d2b-a6385a585601@I-love.SAKURA.ne.jp>
 <daad75ac-9fd5-439a-b04b-235152bea222@I-love.SAKURA.ne.jp>
 <CA+fCnZdg=o3bA-kBM4UKEftiGfBffWXbqSapje8w25aKUk_4Nw@mail.gmail.com>
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <CA+fCnZdg=o3bA-kBM4UKEftiGfBffWXbqSapje8w25aKUk_4Nw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2024/07/02 0:10, Andrey Konovalov wrote:
> This is weird, because if the metadata is 00, then the memory should
> be accessible and there should be no KASAN report.
> 
> Which makes me believe you have some kind of a race in your patch (or
> there's a race in the kernel that your patch somehow exposes).

Yes, I consider that my patch is exposing an existing race, for I can't
find a race in my patch. (Since
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b96342141183ffa62bfed5998f9b808c84042322
calls get_task_struct() when recording in-use state, report_rtnl_holders()
can't trigger use-after-free even if the thread died. Also, since previous version
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=5210cbe9a47fc5c1f43ba16d481e6335f3e2f345
synchronously calls synchronize_rcu() when clearing in-use state,
report_rtnl_holders() can't trigger use-after-free because the thread
can't die before calling put_rtnl_holder(). The variable "now" cannot be
0, and !cmpxchg(&rtnl_started[idx], 0, now) must serve as a serialization
lock when recording in-use state.)

>                                                                At
> least between the moment KASAN detected the issue and the moment the
> reporting procedure got to printing the memory state, the memory state
> changed.

Indeed, the exact line KASAN complained at varies suggests that the
memory state is modified by somebody else.

>          As this is stack memory that comes from a vmalloc allocation,
> I suspect the task whose stack had been at that location died, and
> something else got mapped there.

I consider that the task can't die while calling __show_regs() from
report_rtnl_holders().

> 
> This is my best guess, I hope it's helpful.

Well, KASAN says "out-of-bounds". But the reported address

  BUG: KASAN: stack-out-of-bounds in __show_regs+0x172/0x610
  Read of size 8 at addr ffffc90003c4f798 by task kworker/u8:5/234

is within the kernel stack memory mapping

  The buggy address belongs to the virtual mapping at
   [ffffc90003c48000, ffffc90003c51000) created by:
   copy_process+0x5d1/0x3d7

. Why is this "out-of-bounds" ? What boundary did KASAN compare with?
Is this just a race of KASAN detecting a problem and KASAN reporting
that problem? (But as I explained above, it is unlikely that the thread
to be reported can die while processing report_rtnl_holders()...)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec7411af-01ac-4ebd-99ad-98019ff355bf%40I-love.SAKURA.ne.jp.
