Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBDHKQH2QKGQE25KVI2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C7701B4AD1
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 18:47:09 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id e5sf1320533wrs.23
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 09:47:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587574028; cv=pass;
        d=google.com; s=arc-20160816;
        b=H3WDHx4UDQ2B4/zghLvHStBCLt76sD0LtvvTUEbO/6zDxWMp+Y2JASiOcaNcelB0v9
         21stJyL7szWH/5Di96OOG3hCZreUsgGlqpCVrOICk8JwwqOYifrvkihb4/fbSwckgRMe
         QnITxvGD4tQjUMlCZeyyrBjQHgMxAKObOeeLAWkfqtqK/SF+qfrfDlE9t+rm8oxFt3xZ
         ad7YVZRVD5c7pEIQ38nB7dL/5U+Mez+Sg2v808bGJlATahWR85PXb9a7oD/Jdrf8c/MD
         00GzbOXNx+dN3Ch4HW1Gl+1rmEk6/BPTecUim9ujDe0mtl7KDyapfljy1JjVX50sHywU
         2XFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=X6LG0AwYzddgzjFTxZF2ZQW2SyAtD7NAb9TwLZC3zS4=;
        b=IjYdzecvrKP6PskM/Exi1d8+Sduz35NIdaNe7djbTPewvKga9+YJHNA1B639peAMep
         wlrVw7KpRpqV+kM+50MQQ0uM8oKdPFZygqKez/sQ9uXSnS5nzRnKMq10dezD2mSAwh7m
         t06t3V+/ecVaZtt08fGKpnfq4Q0S1lxfo7FNQY2mWiLji+M21dPEJvS9vihpfvr2uxv/
         Fgpvg1reSr2rNVdzBXoq1qZMA2nflbWJZbRsVM1Tevms9U/wF/ykqytRsVDot6snIaOf
         3ybLC1bfZKG6AYYurysIyvU5NFFxRmNRs/5dFmuOGzSpQB8fmC/hd3U//LyrK9FCrAMO
         kwJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=g1VyvLou;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X6LG0AwYzddgzjFTxZF2ZQW2SyAtD7NAb9TwLZC3zS4=;
        b=QUUYDa3KVEtImjdKvnnN+m3rIcpSWvsINo3l0EDABtDLKMMgK3UU+HXFFDkjqCDrwq
         KBmojHotDVSR9TxMeCbvGzUV+/OC9YCnRueUsmWKt3m21eALSjIFXGwSJKHdVlS9du5X
         pfHzkhgSkT6bp3vHqLj2906qbpuaef21Bopa5V79CMhr2JYnwR4S9E2fz+DuyaRzyTqq
         xUIcpFADG08E519PXqPEPw/2tzySxz4FnYsECzrsa5YlKlNLRu9yG2H0AOMJGpLBrCK2
         raT6pVHcYO8zGPRjBXpZ4iY9wmVW+Z87F/9eFSiZqaoEJUoBZEqb26FMsgc42tuQEAJX
         Yfrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X6LG0AwYzddgzjFTxZF2ZQW2SyAtD7NAb9TwLZC3zS4=;
        b=Qfb1PHq0QUDyAez5S3ma/BBHJTydzQQTLGj7rGDaKQfezTo9tgTEgKo5kpcEg+M4Gg
         KNO0x/OR020gMU8NbhczsGM1QP90F8vpHMlV9ZKMYKy5haYQkuaaWtrGigpeH3QCt6AE
         JiBZAj3DpKzTbYjU/rq0LFYjbA1wEAtUSC7eLgnQ1IzmcHgnpPacskfqkMHDoGi2q5G5
         4pjoyLPRSWtaPHRL4PefvbVpVPVnrERrnPg6Kh6uPPKn+aRZO8VVl5v7a+PYi9KVhROB
         UnOYzXVYhdCKFHm2YIloZOoG8unHAsi3UX2SAR1F109Z9Gn9rTqI6MSpXmHE8fUboeFe
         8ZxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub48roQzbbS/98AfovVF0mZJYmOfrmbxpM9N/9W0juvraUmbAAx
	tdkQLn4zSnZJSOi+jKLquo4=
X-Google-Smtp-Source: APiQypIn89nYRj2wIhpH0fCTDe47IA3AJPyrg5jbDhWbcuS+RAZAYfa+/3kEnTvdue4McyeZnGmVlQ==
X-Received: by 2002:a5d:4252:: with SMTP id s18mr3187861wrr.367.1587574028843;
        Wed, 22 Apr 2020 09:47:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4a83:: with SMTP id o3ls2189028wrq.7.gmail; Wed, 22 Apr
 2020 09:47:08 -0700 (PDT)
X-Received: by 2002:adf:bb0d:: with SMTP id r13mr32748519wrg.251.1587574028322;
        Wed, 22 Apr 2020 09:47:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587574028; cv=none;
        d=google.com; s=arc-20160816;
        b=uATF5M4a7OR2vSgK7CJSfNEU9GRY54AuqNSeIpmlxDkU+Gu5dRJI8k17+JPgplo6ej
         NbFGFeTE2TTq58z4eMB1g0PDlWEilTPrpn5IHSSv2oJyZmVC9H5bVXJKiJoSFXvRBdS+
         Rl3A5p/FI7p8i/HS5Jlg2gk5YTlNR4Vw08xAJyJjsUDc7LFe8Zbj+KB+aPUE7F5YKYpM
         QoL94rzMi3tZIbgOddDa8QiSwom/9/TCCQZepMr54JJje04zDcj9CUQTKOWaRcrKs+yd
         sz6zJLmFTWZ46uY4/Rq6DGz40/D+Bat5Ea1y5vhSA3dIYSCiAHlpeWxchOEY5UPEjAgY
         /MYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=L/jcch1ERCY9r/gPK3XdKvpbttP84XCrGMsNvSSDSMk=;
        b=mNeNJnlso+o/IsHBOsY3KE3mfGn3OO8HV5lMH43+/wNwTuYkev0oBZ1QbxMiIyuzDM
         igHqazVNWrqtrvqwwflqmcEz9NlxgfqoXHV4PJG6Cbz66oqMovZl3krVn44r6FnVoNSh
         W4WV1VgRDGd9GoxzszpD6JHMAit4k9goUUdWIKyqW4k9zJOOVTowace/VPQHk5zhL4jM
         V05KSpLPBT5oS75qoXtT6nReiuQXeyOoHcWVE0rYCXAuSg2fsw7UQ2hFVgl11OGIPwKa
         tMRemyUOaBKDdYTjangDFCzfyEl/p63Gj4pA1b3eYtub7lSDEXdSc7corq+3TPBNNx+P
         zzwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=g1VyvLou;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id q187si424149wme.2.2020.04.22.09.47.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 09:47:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F0DC10099981D244BC6B235.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:c100:9998:1d24:4bc6:b235])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id AE4FB1EC0D53;
	Wed, 22 Apr 2020 18:47:07 +0200 (CEST)
Date: Wed, 22 Apr 2020 18:47:03 +0200
From: Borislav Petkov <bp@alien8.de>
To: Qian Cai <cai@lca.pw>
Cc: Christoph Hellwig <hch@lst.de>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	x86 <x86@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
Message-ID: <20200422164703.GD26846@zn.tnic>
References: <20200422161757.GC26846@zn.tnic>
 <59604C7F-696A-45A3-BF4F-C8913E09DD4C@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <59604C7F-696A-45A3-BF4F-C8913E09DD4C@lca.pw>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=g1VyvLou;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Wed, Apr 22, 2020 at 12:35:08PM -0400, Qian Cai wrote:
> The config has a few extra memory debugging options enabled like
> KASAN, debug_pagealloc, debug_vm etc.

How about you specify exactly which CONFIG_ switches and cmdline options
you have enabled deliberately? I can rhyme up the rest from the .config
file.

Full dmesg would be good too, sent privately's fine too.

"etc." is not good enough.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200422164703.GD26846%40zn.tnic.
