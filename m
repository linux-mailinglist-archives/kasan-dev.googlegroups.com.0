Return-Path: <kasan-dev+bncBCTJ7DM3WQOBBG76UPXQKGQEW3OS53Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 24F28114119
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 13:59:08 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id y18sf865169ljj.16
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 04:59:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575550747; cv=pass;
        d=google.com; s=arc-20160816;
        b=ldsdrh+KsgCtaLifTtyS6Ql36b9BxWsDRiJUkOfqijwuHeIR029ZmjIdQ8geAAq82m
         00Z7KtnUKzU5RhHwqkgk/22TaxNAHU74slrar95xmUIu1tdsIYJJPstmGxllsAGnNXJZ
         O/tIqT6p54XM37RdsUeigxeRDyXmIW82DlLerRVvVGU3BVQJSCHaCYvgEtsSs665MJij
         qM1ML0iLEu+nOY2xOcy8fawa+Gh1hENraL65jAN44jgRMEOc0yXuC9mO4zbc/xZiGpuV
         Dx9+ZEyRZNq8E3/meGUgb2r1v3o22+rrIJOkIRKlXB3/c1muCyGPs3+SoZMigQFkg9VQ
         RkoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=vCpz/kh/WZDP89QwPnF683t0SDXsvi2zuXOUXjZkbyA=;
        b=aN3Zy3QmoSVE1mgCiNDa1hz9n28D2uTowx0zs9/MqjOMKqx+iYD+/v2AJRq3u07Bps
         YGIyF6BM34Ykh0DPnPzW+mXSwhYo4KoSnv1i9L23AzEpwdU+AcAXvL/BU0a3nJ/N5+H8
         mySQiJoqxmY2j2phwJDWadTY/0YhfSLzwYgr81AyAavgyh8/D/kKWhBFvEZJ5wH6APJa
         R2/U8Ab3bVcU4Ghsni/4IdJP/X/MskqhnMGshYrutb9FpaFnh4E/F1Pj9sSuuKZBDjZq
         qHbXZMnWMiZRK/UI9XhbAQSthCXm0y5FfG36U05SoWoUuSpRybW5/FuTyUdVPj7koJ3Y
         l26w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vCpz/kh/WZDP89QwPnF683t0SDXsvi2zuXOUXjZkbyA=;
        b=Ydpb1Lexb9K+jgk43s7oF7AG7QbPwDUVrR/E5yBm63NIWgElUL0uuAoRHtANtYESks
         uidZ2fjb1ogRy1gmF39/TEYt2YVinRpHzK8kTkuw3QYhdewt+JuxG9YPQluuu501KFF4
         89RCwW4EpP148aJ73O1c61h+e8WXl4JXwGLGq2+w9pF1lhjtGeGO+t60JHKUkHV+d6W3
         wRqxF1YFtIhKHRSHBESTMDry0H/IxEtHbdgpK0ERdpeRQmn0XbH4YLiRDSXNkGkqRad5
         s5c71v7YXMeRvuN0vUE7C/wkJmoAdS4tbHyZDTNpvd4Fy+46ItSzqdYhFUexI5t9ovcx
         36Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vCpz/kh/WZDP89QwPnF683t0SDXsvi2zuXOUXjZkbyA=;
        b=ek74jCA6wL9YjF+MthTNP36mXPzfsxWs4OKv6hHBHuTU0pe4id3xNJ2aelvuLgihpR
         gXFJ7SqoZrgE+ZjwkWIIKw3m+g7La65dU3+kthpUj0Ajy4ExP04vDWCFOtVZtpZkW10t
         VOzwem5Sh++dpECydGP9xVNLJmprPTfI9RSMdxhOLEKFlKAg0BJ7c594rY2O7mq924SN
         qZ/KOFdNoPKM4CjbQj1pdrKHB1XPIpA03/9xRfAsV0YHpL2zbeN453hukAcxGw6muK9s
         cXadra0vE/Xs80l3sUcWeankhabnj9nIFu+CodRZ5IOoWpYyku0Fm8PNBUWQnUw/TcU/
         8Xng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWV8sgOy4iTyEoG/6XWJ7ClaoG11axDD/vT5GF0YdybaWIh10ri
	qd8RMRrgPMdL0XeVsCcV+WM=
X-Google-Smtp-Source: APXvYqy4DacoFGM+TG+WuHWQpCBffmlcsenAT+Ju1al3/vHlSeEt8I6euoKlbO6bkGqFaclEoWH1QQ==
X-Received: by 2002:a2e:90c6:: with SMTP id o6mr5439161ljg.93.1575550747759;
        Thu, 05 Dec 2019 04:59:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:8488:: with SMTP id g130ls288212lfd.11.gmail; Thu, 05
 Dec 2019 04:59:07 -0800 (PST)
X-Received: by 2002:a05:6512:209:: with SMTP id a9mr5240289lfo.157.1575550747127;
        Thu, 05 Dec 2019 04:59:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575550747; cv=none;
        d=google.com; s=arc-20160816;
        b=MJfGj0NgubIkFJy3jGGSQtdT2CQhn1JSuE1jSV0Sm0fTiOzktJrAQ+pi6n1um5yyas
         A8kcXY1cEzvzjbPQ26Ki0O6OLkjJTtwpU5rReazMswa8FIuKoZfIio7bDwJV6d4uAt/Q
         h8FU2ZXCiODps1xCIGUPQUlSP0rZHCSFN+w5QOH7t9CV2etIAlLXvKaRJppM0wJWkbGG
         VRYAguz6tn8aBamyejqaQjRQJR0eSy1r11zc68zbWalYoRLkZ7ssolxpgqZUwDhkXU4G
         IV7muoY+zWyKwpP8bQBmJSKaemJC8TyoZ2IdmiBulGINiTvnDVXddS1SH2dKIPaMtWn7
         G3Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=nj/ExjOy04k2h5DR9OkGDidH/Xuq6qOKnSyyWk7whM8=;
        b=KKI8w5NiO0IvgtZTA5vHLukMapAnAclN10rzh8eRmCHz4uqC8OctpBTRDiVv62Lu8T
         fuSvz1eYuROSUUQSNBKz5ks0BsmlJ322GlMTJ1LrhBKZZ7EJbcLU5YwTudhw3iQ80C9+
         ansJJl5jmTrSnYVdU4VF2vzlNsEPiUl83oeYKw7fumazeXvQl0361oB2VceAofn9EjSj
         ni0YxDTJbuKWdSf5aKFZ3yfazXOLuBWpxbuQ5GZSbgvxCVPGYf/uxiVIfBxmWEH5itLk
         C/ATHR2i1FjVZYSumlYiEhxUKMrW00ljK1pCt+vqjL9NJORyozWkkapTpq7QpyD/WcXo
         sdaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
Received: from www62.your-server.de (www62.your-server.de. [213.133.104.62])
        by gmr-mx.google.com with ESMTPS id f1si536433ljg.2.2019.12.05.04.59.05
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 05 Dec 2019 04:59:05 -0800 (PST)
Received-SPF: pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) client-ip=213.133.104.62;
Received: from 29.249.197.178.dynamic.dsl-lte-bonding.lssmb00p-msn.res.cust.swisscom.ch ([178.197.249.29] helo=localhost)
	by www62.your-server.de with esmtpsa (TLSv1.2:DHE-RSA-AES256-GCM-SHA384:256)
	(Exim 4.89_1)
	(envelope-from <daniel@iogearbox.net>)
	id 1icqii-00073e-Qh; Thu, 05 Dec 2019 13:59:02 +0100
Date: Thu, 5 Dec 2019 13:59:00 +0100
From: Daniel Borkmann <daniel@iogearbox.net>
To: Daniel Axtens <dja@axtens.net>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	syzbot <syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrii Nakryiko <andriin@fb.com>,
	Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>,
	Martin KaFai Lau <kafai@fb.com>,
	LKML <linux-kernel@vger.kernel.org>,
	netdev <netdev@vger.kernel.org>, Song Liu <songliubraving@fb.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Yonghong Song <yhs@fb.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: BUG: unable to handle kernel paging request in pcpu_alloc
Message-ID: <20191205125900.GB29780@localhost.localdomain>
References: <000000000000314c120598dc69bd@google.com>
 <CACT4Y+ZTXKP0MAT3ivr5HO-skZOjSVdz7RbDoyc522_Nbk8nKQ@mail.gmail.com>
 <877e3be6eu.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <877e3be6eu.fsf@dja-thinkpad.axtens.net>
User-Agent: Mutt/1.12.1 (2019-06-15)
X-Authenticated-Sender: daniel@iogearbox.net
X-Virus-Scanned: Clear (ClamAV 0.101.4/25654/Thu Dec  5 10:46:25 2019)
X-Original-Sender: daniel@iogearbox.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as
 permitted sender) smtp.mailfrom=daniel@iogearbox.net
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

On Thu, Dec 05, 2019 at 03:35:21PM +1100, Daniel Axtens wrote:
> >> HEAD commit:    1ab75b2e Add linux-next specific files for 20191203
> >> git tree:       linux-next
> >> console output: https://syzkaller.appspot.com/x/log.txt?x=10edf2eae00000
> >> kernel config:  https://syzkaller.appspot.com/x/.config?x=de1505c727f0ec20
> >> dashboard link: https://syzkaller.appspot.com/bug?extid=82e323920b78d54aaed5
> >> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> >> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=156ef061e00000
> >> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11641edae00000
> >>
> >> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> >> Reported-by: syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com
> >
> > +Daniel, is it the same as:
> > https://syzkaller.appspot.com/bug?id=f6450554481c55c131cc23d581fbd8ea42e63e18
> > If so, is it possible to make KASAN detect this consistently with the
> > same crash type so that syzbot does not report duplicates?
> 
> It looks like both of these occur immediately after failure injection. I
> think my assumption that I could ignore the chance of failures in the
> per-cpu allocation path will have to be revisited. That's annoying.
> 
> I'll try to spin something today but Andrey feel free to pip me at the
> post again :)
> 
> I'm not 100% confident to call them dups just yet, but I'm about 80%
> confident that they are.

Ok. Double checked BPF side yesterday night, but looks sane to me and the
fault also hints into pcpu_alloc() rather than BPF code. Daniel, from your
above reply, I read that you are aware of how the bisected commit would
have caused the fault?

Thanks,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191205125900.GB29780%40localhost.localdomain.
