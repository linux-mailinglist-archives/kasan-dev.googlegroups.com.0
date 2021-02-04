Return-Path: <kasan-dev+bncBCSJ7B6JQALRB6F35WAAMGQEPUA3ASI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id CD65B30EA49
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 03:37:45 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id k27sf1259854pfg.8
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 18:37:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612406264; cv=pass;
        d=google.com; s=arc-20160816;
        b=VjammlaYPKb4daq/VT2AaWkFzy8xLU37fnCQOYVYoqfhUbbSDeZzGibsedaQmL1XLe
         PoOn0u+1feO4l5iFEAubWP2rV1ubLv91z5gdRWrj1pxnsdhXsoa4brTM4RGDBXBNgXva
         5UtWYdYT9bjCOHjJ2ixL140VdUfrjJV5zrvIhmzAZSc1QYJWV378FJT7EaIgDrQxocyf
         RdGWQhPE+VUDBScHDTdu+OF+xaHeSUSYA48478L86rOOKDAg5CwbjRMSo4CY2nB+l2YD
         BZK8olZAqxbD5xVd/Yvv8MCMVoK4a9hgOpicYLUrPGZwso5CMGAqpf3KlCnddsDqiZ7w
         P+pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=y+4gVvVtcYVMnCbssOcfq7NpuW9GXE8pKRVFqBuHhxo=;
        b=GzvcUvUd2T2q5g+7Z5JG6hDpXaedTiaSFfgb4QXOR1xP7ZiHKCd5klFQLAUbCPoFjE
         scCH2IN5h04dEqtLtNQbKZfh52MCgSISKJ1jx6jf7Dumi6INvgPTG3usiXhgpdLH7AI0
         AsKgTNUY+sjj7n9C4dh43Symw/L7oFlXMD4kS391B4Y9/sYBOOKcS9xhSi1DVeAcmLya
         K1w75yhEri5cZhqy7Gm5GLfmMsCDe+JC6rLIJlyD5robiLYDrwpRYHeLQ43MRjQoinp5
         45iiv7v/hYyTCdAMub2Nbx1Qevj39nt8rMZOYhiQhbvpZA56547RpDf2fpD5KNfuJgPj
         xHqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JI8Q5PQF;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y+4gVvVtcYVMnCbssOcfq7NpuW9GXE8pKRVFqBuHhxo=;
        b=khhqhUBDQB2kwa9+HSk7mPWLlAtRJprdsMjX5NGxqz5OX6bHUVJbWvNJtF8Igw0xa3
         sUArStp7IPSarRLU68bwnkLXB32P4CtpEoEnqhPt7+wBY1U8FiiPyCeYEGSGS0OQjuec
         qrCApcXya5+0Vr43c5QYY8RkrIHQjwEWBYtlYTqmP7SdhY/E4wS+VRSsAMYgmTTPVaIG
         pbxAsHmKklmKGOPd+bnSPRWf7PQRWw5DZK+J+CeBlywBMUrOEwirALGDv8xeW6RSWyk6
         dj4rRGD35QOAJRaqk72iq4EWbsqVxGAYmtYZ6lAgOcGcdgx1/X9PaG7Ke1t7ARiL7PB8
         6QKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y+4gVvVtcYVMnCbssOcfq7NpuW9GXE8pKRVFqBuHhxo=;
        b=TKfG3uyErErAVwmaCYsdP5l/R+DKpZ9hX5kSj2slHCP+I44a9vM7gT4YRJDbm+03mr
         9GyOLPcJeCZ0wXa+6BkSDyqxh+1uah4TI6KqM2dqJXGD9Kt8wrLr3BR+H+JG7ZL5r85k
         z+UF2EY92D0m/mAL6kvMEJk1ber8s4hSNsxtuYG8DSZCd4bR8rH3lUNxAhhWQ95yXuwq
         TQ13YtX+K361mQJFOaHmSzNpA6u63IwCL9rtcc0uSfVrc7/dlb95mRXDQCVFLRpvLMsT
         pxV2T1VHm1779FxlP7DDsuXIhTVR4sU+aMGN/3/3ten/WGzHT6ZhORD/u7s9SeSrO6U2
         zuHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317Kb2iw677Gz3tiP47WY7Wx+TIHJ5OQ8/i1Die5E2EXQptSKR2
	C1Mi3b4cWy8zLUbmvzFfj3A=
X-Google-Smtp-Source: ABdhPJyiRcS+CRCR/8Spf6IXHUA026kmssYqgOD28vlvIhld+dZL3i2KxPYyoA0pHAoR2pUw+BYX2Q==
X-Received: by 2002:a17:90a:1082:: with SMTP id c2mr6112712pja.183.1612406264353;
        Wed, 03 Feb 2021 18:37:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d2c1:: with SMTP id n1ls1925777plc.11.gmail; Wed, 03
 Feb 2021 18:37:43 -0800 (PST)
X-Received: by 2002:a17:90a:7608:: with SMTP id s8mr6204302pjk.105.1612406263682;
        Wed, 03 Feb 2021 18:37:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612406263; cv=none;
        d=google.com; s=arc-20160816;
        b=Sk+F14Ee8s0FYTiheimqQWl0JRb9WKGtSj5ZGIa6AwCvT0T7Wm/d7zn+/V8pPC8lff
         FfXQ0mskcbK7z/iSqtd4MmHfBXETL9aVGFeaJuD8p9zuLI6aTSwF5rJxOUkUAovUNQ9/
         zHUVWpSNRJm+p3maxcwjQMX2Ur35r6CmZ22e8oPxmFFyYKe9+Ht7lVnkL3Zd3e03ocAk
         xz1VHDMrzrnmJKd9kPVn/CpCU05Yd1bFIkaYnz91JCZuIX61PMnyAo9PWK1dFahaaaLE
         +8PbYkOQsbTIPN/t1K/VNkGUT+FAY1YqdGmW2GF51A5kXHsZhusy+SfyoepKrD91SlOY
         sGvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qhb2kXItW2mHNSz2e91apSBwbAib3godlZyK9gF1DQM=;
        b=nxwhfNHa8Edvz8Z5fU5rIoIGKRMeEB9jViFROeVJlbMnYO2JBkD2VwQmTPBATdhq5N
         eyodOrVp8ibxo1Lu92wdJywjHi6oUy/5P3sp3e5DNSel+7VOGa4Sov6W+NkE29hiRjwq
         CTngqyp+MmlJB6ddYCMFdcUC/6Ygn6iim56AxnkN7r0/URee+gzx+1fw69R0zczoyHxC
         Ab7lgMK+33d3/GYSNgX+CfKjHz0Q9I4Xv+Lg7MV/4+/AcLuTjB49Bp/XuWp/DBlnA6H5
         ovG54tGeqao0PXXHjtdgcELLU9TlBfb0HhwBRSVsThOOJAlJoC3nqOPbuTSDYlVOE7PZ
         zY6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=JI8Q5PQF;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id r1si204481pjd.2.2021.02.03.18.37.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Feb 2021 18:37:43 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-597-OH7evkT8PvyBFzDkzbNQCA-1; Wed, 03 Feb 2021 21:37:40 -0500
X-MC-Unique: OH7evkT8PvyBFzDkzbNQCA-1
Received: from smtp.corp.redhat.com (int-mx05.intmail.prod.int.phx2.redhat.com [10.5.11.15])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id DF32D801961;
	Thu,  4 Feb 2021 02:37:35 +0000 (UTC)
Received: from treble (ovpn-113-81.rdu2.redhat.com [10.10.113.81])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 383D85B695;
	Thu,  4 Feb 2021 02:37:21 +0000 (UTC)
Date: Wed, 3 Feb 2021 20:37:19 -0600
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Ivan Babrou <ivan@cloudflare.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	kernel-team <kernel-team@cloudflare.com>,
	Ignat Korchagin <ignat@cloudflare.com>,
	Hailong liu <liu.hailong6@zte.com.cn>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
	Miroslav Benes <mbenes@suse.cz>,
	Julien Thierry <jthierry@redhat.com>,
	Jiri Slaby <jirislaby@kernel.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel <linux-kernel@vger.kernel.org>,
	Alasdair Kergon <agk@redhat.com>, Mike Snitzer <snitzer@redhat.com>,
	dm-devel@redhat.com,
	"Steven Rostedt (VMware)" <rostedt@goodmis.org>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Martin KaFai Lau <kafai@fb.com>, Song Liu <songliubraving@fb.com>,
	Yonghong Song <yhs@fb.com>, Andrii Nakryiko <andriin@fb.com>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@chromium.org>, Robert Richter <rric@kernel.org>,
	"Joel Fernandes (Google)" <joel@joelfernandes.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Linux Kernel Network Developers <netdev@vger.kernel.org>,
	bpf@vger.kernel.org, Alexey Kardashevskiy <aik@ozlabs.ru>
Subject: Re: BUG: KASAN: stack-out-of-bounds in
 unwind_next_frame+0x1df5/0x2650
Message-ID: <20210204023719.sbwh7o7un7j2zgkd@treble>
References: <CABWYdi3HjduhY-nQXzy2ezGbiMB1Vk9cnhW2pMypUa+P1OjtzQ@mail.gmail.com>
 <CABWYdi27baYc3ShHcZExmmXVmxOQXo9sGO+iFhfZLq78k8iaAg@mail.gmail.com>
 <YBrTaVVfWu2R0Hgw@hirez.programming.kicks-ass.net>
 <CABWYdi2ephz57BA8bns3reMGjvs5m0hYp82+jBLZ6KD3Ba6zdQ@mail.gmail.com>
 <20210203190518.nlwghesq75enas6n@treble>
 <CABWYdi1ya41Ju9SsHMtRQaFQ=s8N23D3ADn6OV6iBwWM6H8=Zw@mail.gmail.com>
 <20210203232735.nw73kugja56jp4ls@treble>
 <CABWYdi1zd51Jb35taWeGC-dR9SChq-4ixvyKms3KOKgV0idfPg@mail.gmail.com>
 <20210204001700.ry6dpqvavcswyvy7@treble>
 <CABWYdi0p91Y+TDUu38eey-p2GtxL6f=VHicTxS629VCMmrNLpQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABWYdi0p91Y+TDUu38eey-p2GtxL6f=VHicTxS629VCMmrNLpQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.15
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=JI8Q5PQF;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 216.205.24.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
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

On Wed, Feb 03, 2021 at 04:52:42PM -0800, Ivan Babrou wrote:
> We also have the following stack that doesn't touch any crypto:
> 
> * https://gist.github.com/bobrik/40e2559add2f0b26ae39da30dc451f1e

Can you also run this through decode_stacktrace.sh?

Both are useful (until I submit a fix for decode_stacktrace.sh).

> I cannot reproduce this one, and it took 2 days of uptime for it to
> happen. Is there anything I can do to help diagnose it?

Can you run with the same unwind_debug patch+cmdline when you try to
recreate this one?  In the meantime I'll look at the available data.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204023719.sbwh7o7un7j2zgkd%40treble.
