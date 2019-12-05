Return-Path: <kasan-dev+bncBCTJ7DM3WQOBB7EHUTXQKGQESM5SSEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1866011415A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 14:19:57 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id g78sf850568wme.8
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 05:19:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575551996; cv=pass;
        d=google.com; s=arc-20160816;
        b=OEqGNB3nflGmobA3ALn8oPptBDSh286TB++/7fqlLnqO8cMYu+HaTv72vGmxuZhLUN
         67YsYP66zT4GZhrYztpD10aBPrFpXwz7MFB1j69xkv6YmdzKx57h1w1R7qtJhnn34b2y
         hgYRknGf7L7F0KFV+oh102ycS4Vead15MsxkgwoZAc3ii/wfUrn8hs83pNXnX0lNEJN8
         5UrSppxJp3N34W6lgeIE4bvoQVxY4Icf2zwTdagfrCQR2W//JpBTVNsQirvZSYpXpdYB
         K/t65Ul2RP50S5YCGZI4D2d6d/2coWZ04OfNVjBSwCz1qkFvtQXaDaacgUiCyOyT2IGl
         /wDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=+4+DXiCO47Zr0pkLpGvvqXpd+16vHTmSIqVdKfFGWRY=;
        b=cyjOfOEDZrOPfD48OtYSDgS1Wu7uZJ3I8ZS1PBCKK0ds7BDRNnYUO6rBRgxZfbW4Pi
         qfiletFUSoIH6ZzAhP8YkznJyyj5ayv07gZAWrfcCdl8TLPMG+MPf2Bm2jQalDFTbbCb
         pAx3ulkb9eaAToocFbqXiYz6qjOlb6aqO2PXlSXh8ARQF2eJAzl6FTKDbvBUDmgMZhh2
         Uvye2q1ziCb25brwkT8dWMkPXdd6FP4IZvkYnw685roO3OAoUktmArt3x2VsonmJ7HEN
         aC20UF90dF6WHg8bwlDuusT05t7Ikth1u7ikeTaDOCtn0lfn0d1NqwQ5homObGd00yn9
         SW4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+4+DXiCO47Zr0pkLpGvvqXpd+16vHTmSIqVdKfFGWRY=;
        b=FB2cmWrlqHO6kSK7fe1xNHFw685Dt1kyiyWFSdmEb+w8Xnv3aHSSNxwosvyBG1lXpd
         6KVhwMnzqvJkbnJV20bakgVsFSNTgkd+7VTxeZis30BlwNX64V4DpHPflLuRoWesNQs5
         WEziNdNa4PNspXFKKQ2iJSl+QZUVJbiR5gSR14jeuqXyjX9eAA/+UIYOyad5AGpc6+HY
         1CA5vRRt7QZ/KXp2RAQEatkTVPZX7gVXSUxEHEmnQHw4iNaQZJC7WDnKKljzUxn0Nqsp
         p8+4gG9DMD8a3irQcMYc4gCp7ae0kW6zB4W1eCU+0CC6Gxszr4PxCOzZnsfQey/5u1tI
         V89w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+4+DXiCO47Zr0pkLpGvvqXpd+16vHTmSIqVdKfFGWRY=;
        b=SUzbRQ/YfLK8u3Ibc94M+sLfvIuJrx+bTL5v1T9lUUUT34IVZaZf9tzof6//RYYdu9
         JZmK0IOraZGJVoI4F98qIxEfNcJUaGnTSI4MyWrIzLla16nctufBklfoa8h7PCkJg1ok
         +/yMVzzkzrl4KbRICUhNu0AJ8ytANzJeSeQ3gFz29Q832DvlBduJ4Oi7RfEs4MTWztlI
         8pgMkoWudlydZzMGlm5oepsw11tLCD2Bt47KvOqEaOuqZ1YULomI7OS3VnxovLmQsHKu
         XN3oqms3ymS4M5ox/A8EyNOEwRpTfZ7Kron3gDr1OfjhBxTBlY4vAQ142otdT6S7OS6O
         w7GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUuRroklpEPE2MWKrVhX02h/O3FOAOCmxROQjFfdDpI3UhiWIZL
	+1eW/gkG/Nfv6dASvIHymOU=
X-Google-Smtp-Source: APXvYqz7Pr08IQ9dtDs4Q9nZBs+iOjcr3mGftSIsYtlA3eDq621NquDK6/SEgHbG9DrgsnrVQwa9pw==
X-Received: by 2002:a1c:a984:: with SMTP id s126mr5226665wme.146.1575551996743;
        Thu, 05 Dec 2019 05:19:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ecc5:: with SMTP id s5ls1229676wro.12.gmail; Thu, 05 Dec
 2019 05:19:56 -0800 (PST)
X-Received: by 2002:a05:6000:149:: with SMTP id r9mr10133164wrx.147.1575551996200;
        Thu, 05 Dec 2019 05:19:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575551996; cv=none;
        d=google.com; s=arc-20160816;
        b=zlw35W7FFJpx5rXpjVub2/q7F/ZqrlTlD/53psPqGqs3NGhWkw2DfgwcaqQo5TXBh8
         Wc4lLSLiZ2ZUc+sDjJxK6oL2Vl9kqfx/dNJKbdPCbbBqURSEmjKKlW4+pCOWbqzcszeH
         MhV1uif9hcoCewu3kuqeWlK3R4bVU0oj2VghobtoQBkuhu2LOETgxN2s/sDV+OGQnNEL
         IHywJ6zy1c3jkl5Z+VoU2vw40Jyfxiyn5Z2ahdU3mZVwCoNyLEUWdSexgp4loeA6XjXW
         Megg8CHPeS2/rEH+ZBSvD31PyF5vmlz5g1V/Zca6mPtZDa0DKeE801ex7bml+wOj3/CI
         oDcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=dg0CfuXxuE4rfOE+L0rgyTqYeSVgDnF7jKMAwV9vCPk=;
        b=vQD+/SPkgZyTwdWyVai6ThJ2z4aqGWg+UNSvimuK1j59Qjv6+pgBUfPNXZh9w8aeHX
         Yq1dhm9IWRfYpPpJ8A4Yy2SUOTxNMOcAqL4BHzzFxVXjNUUYRnmpIbLZtLrEHoC2fTdS
         7roSu1fsvRp9PXtrbs9K1fiRbAz7lK/5Irir8TmN7axQlkxmml19rDppSFj4sbltOpDR
         nvdCotpXiYoBzDV6i5kUHdl46fvTl/jccC9DHLJ5UGLPsysx6O7yMxrcTFy69fsiTrPm
         py4z2IxmG3N4MAEx5rMQ5LaGb1a4HIUZT8+WkExxU3kHE+LT3qvmPaS1Zm1LbtpA+KuJ
         tDMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) smtp.mailfrom=daniel@iogearbox.net
Received: from www62.your-server.de (www62.your-server.de. [213.133.104.62])
        by gmr-mx.google.com with ESMTPS id p16si468022wre.4.2019.12.05.05.19.56
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 05 Dec 2019 05:19:56 -0800 (PST)
Received-SPF: pass (google.com: domain of daniel@iogearbox.net designates 213.133.104.62 as permitted sender) client-ip=213.133.104.62;
Received: from 29.249.197.178.dynamic.dsl-lte-bonding.lssmb00p-msn.res.cust.swisscom.ch ([178.197.249.29] helo=localhost)
	by www62.your-server.de with esmtpsa (TLSv1.2:DHE-RSA-AES256-GCM-SHA384:256)
	(Exim 4.89_1)
	(envelope-from <daniel@iogearbox.net>)
	id 1icr2v-00019m-4m; Thu, 05 Dec 2019 14:19:53 +0100
Date: Thu, 5 Dec 2019 14:19:52 +0100
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
Message-ID: <20191205131952.GD29780@localhost.localdomain>
References: <000000000000314c120598dc69bd@google.com>
 <CACT4Y+ZTXKP0MAT3ivr5HO-skZOjSVdz7RbDoyc522_Nbk8nKQ@mail.gmail.com>
 <877e3be6eu.fsf@dja-thinkpad.axtens.net>
 <20191205125900.GB29780@localhost.localdomain>
 <871rtiex4e.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <871rtiex4e.fsf@dja-thinkpad.axtens.net>
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

On Fri, Dec 06, 2019 at 12:10:41AM +1100, Daniel Axtens wrote:
> Daniel Borkmann <daniel@iogearbox.net> writes:
> > On Thu, Dec 05, 2019 at 03:35:21PM +1100, Daniel Axtens wrote:
> >> >> HEAD commit:    1ab75b2e Add linux-next specific files for 20191203
> >> >> git tree:       linux-next
> >> >> console output: https://syzkaller.appspot.com/x/log.txt?x=10edf2eae00000
> >> >> kernel config:  https://syzkaller.appspot.com/x/.config?x=de1505c727f0ec20
> >> >> dashboard link: https://syzkaller.appspot.com/bug?extid=82e323920b78d54aaed5
> >> >> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> >> >> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=156ef061e00000
> >> >> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11641edae00000
> >> >>
> >> >> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> >> >> Reported-by: syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com
> >> >
> >> > +Daniel, is it the same as:
> >> > https://syzkaller.appspot.com/bug?id=f6450554481c55c131cc23d581fbd8ea42e63e18
> >> > If so, is it possible to make KASAN detect this consistently with the
> >> > same crash type so that syzbot does not report duplicates?
> >> 
> >> It looks like both of these occur immediately after failure injection. I
> >> think my assumption that I could ignore the chance of failures in the
> >> per-cpu allocation path will have to be revisited. That's annoying.
> >> 
> >> I'll try to spin something today but Andrey feel free to pip me at the
> >> post again :)
> >> 
> >> I'm not 100% confident to call them dups just yet, but I'm about 80%
> >> confident that they are.
> >
> > Ok. Double checked BPF side yesterday night, but looks sane to me and the
> > fault also hints into pcpu_alloc() rather than BPF code. Daniel, from your
> > above reply, I read that you are aware of how the bisected commit would
> > have caused the fault?
> 
> Yes, this one is on me - I did not take into account the brutal
> efficiency of the fault injector when implementing my KASAN support for
> vmalloc areas. I have a fix, I'm just doing final tests now.

Perfect, thanks a lot!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191205131952.GD29780%40localhost.localdomain.
