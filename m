Return-Path: <kasan-dev+bncBDN5FEVB5YIRBWGHZH6AKGQEUWW5DLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E7BE296949
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 07:02:18 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id f2sf306074pgf.5
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 22:02:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603429337; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oqkh0wQrBtDBjP/fGsaRgc7x81mYRBdtt8hfJnyeo9+yWu4bnsm/zrPeqrC4hj8idc
         UrxZ8+kkqxHtTGDNc57mTptOYZluiGZ1YbpIK2cOF7dpKwClrkhJ3eWdqCj2JEByy8Cw
         1npUmW4cHYL+6U3oPvf4gwMr1fdAP0RMr0IHKVQirsBZ4fy/Y0+ZOjvbFPA43uM0iOXV
         aWIrvg5A54drpcvbQFeLy7bnYZBlefV3otGxHN0RnPq2b6FYPW087ESKLeZqlRSPW6cm
         v1kDE850MxVhLJDZGtgZX0JgiRzxYCS/+OICoF/+G/lHJkZBNs8T4yQcbzcXH7QzC/LP
         YKHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:ironport-sdr
         :ironport-sdr:sender:dkim-signature;
        bh=i4MSEZnDKHolcOpaLtSDW1JJESXN0zz7tP1Gw3r1jSA=;
        b=YicYdWmrTXWfTgTgscPqOVZHyj0bc5fVs5rueSwyqfu20VGgC5IdvzWtpbvDWwT4IX
         xklTWhxw7EoSaJEQb0a5OLdpzM2z4PFxcLMJSN9JVapJHhxB1bpdtwRoH1a2es4bCPgD
         MTQEuD7vfqewQKyGF/1gaM7ZwVEmf1ODH1nn+opPxB52hra1vNRGAL89MarUP0/CscpV
         YIfo0e27ikqj26LQu7dfLGS3TZTFftLJ1KUWyA3SmBhFOQK+OStBy6Aquc5rlOcsvgfS
         s1s1Sqc3wdnYp7B9k1WQidTZlpfiWRVrR6fLm2ySdO0IwpSMeHnM/0eodWaSPWwcSgpU
         pmpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=i4MSEZnDKHolcOpaLtSDW1JJESXN0zz7tP1Gw3r1jSA=;
        b=MdvqZtYKEwfPFqjNl15FHGVBp3YVhsKY1IEp3v13rIAe874mteuy3QShzvQVJ+ZcmU
         uRFLFxrPCTNUXkH/P4jpzIRH8u06RaMVyBkM6dDdUXGYxolE2cKGUl01Of4euObga4h/
         mzpasprkYvJZVdnooX/pr2U79MkZsih8DARxBpTlb3+DC0H3sB13+bRSfrgp4yU0HgYs
         VcD7hwVowJ4qn50zXTQPanzJbZ1fqtTaJxHYclAt73dJ5LLcLyV9WFZoE8jG5J0NhpP/
         lsC2tRy1k8XqRpybhwJ0ylkOCYODrEzCuK+7KBQuuFUSzoLRD04/2/HzetKSfAITtI7K
         Dgvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:date:from:to:cc
         :subject:message-id:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i4MSEZnDKHolcOpaLtSDW1JJESXN0zz7tP1Gw3r1jSA=;
        b=ZFP5E22qU9hQ4dwC6Zl37yBGSvWBLrv2Lhqyt/3+/hF4M3hU7cvi5p9pRxZtcDOcCK
         Zgr0vexulMNjHA0Ut7dLBeuMJlYUYW4wrIhabUsefJajuKUhvHXix0eIj2dw3Nua1BZX
         ZgTULgkTyxppQwGKIpASTFzIZqSrLnKFyWJ/n3KOkxXxxJd4PXsC9z935PezKSUrdx4n
         FUbeXOn84sH38t9xG4KbmJrPSLFuWZ4FgI9qJk64Pd5YcdXE1VMfTSBH+iXdM34vvvpS
         atG0SW30+2VtrU0VlBNJ6cm1sdRNr3bsD1Ds99lp0ZfW1CS12zNnwc/xYWey3K3d8xRK
         fDtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532iNeoGNJwYKDsvG2O+hL+UBc1O+1dPWfd8GUOihWZ2aEBceJ4d
	mgO9dEIWMqik6wBHCOdvJb8=
X-Google-Smtp-Source: ABdhPJxkBBi7trRZ18WU/5DvOBifSSXIusAzqQZYKR/vJ1s2n7p4KgWXV8m+1ZmlFr/FjhfLQIOsTg==
X-Received: by 2002:a63:cc08:: with SMTP id x8mr642385pgf.229.1603429336847;
        Thu, 22 Oct 2020 22:02:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:da56:: with SMTP id l22ls98015pgj.9.gmail; Thu, 22 Oct
 2020 22:02:16 -0700 (PDT)
X-Received: by 2002:a63:3d4:: with SMTP id 203mr718461pgd.0.1603429336343;
        Thu, 22 Oct 2020 22:02:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603429336; cv=none;
        d=google.com; s=arc-20160816;
        b=weWxkts8NnOctna+SjR+0e6kgRcxzQiXw3DWGyH4U4udWS5SCGMN7VpzWvrk8HN12z
         zXdL6c9JlbGySWS8zeWqhBhgFJbFEAA1N7SDEylSWdCCiIO4s26fmKSKLPe5J1kNKqgu
         m8i5+BWCZHxQGWqfrzWACZnHZMlrIHeO+OU05PbFtQ529/6Wcwsvz1nMB0NslYaZMP5h
         GRVf+GI3gz5dGtu2GS9U2RvIkl+erFCjZ8lepPZzW97MQk14LoC5dGKmgJnQORI0XrzN
         Q7oKsGC4AE1/YDyBbOuZRYBpV1+MEAfpTGkmkcvaOdChoAGjc4S7YEAM/kWCuyV5afKn
         vuLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:ironport-sdr:ironport-sdr;
        bh=YsgGD5hfMHATAumVUNLI+ckTiTjKOa1edpH1TgOQ//E=;
        b=0QqnRSPk2Rp6HGKxiAqU7SrqeKrORXxl20SRotJH+Y0pU0bxpn0W6zuhq49weyWlkS
         Z3O+hjzUxiDWzvkK6EgSo/pOvJkV8U7aGhz2mHDdPcoKQU6N+f8qmpwAOxhhfpKx/Z7R
         t+CbUbRoQHYQiyAxD2pVLwPMquBXL6+r6CyN9A3O5+TRjVai4UB6HEaBSWW0aaQLbYJX
         BD5JIv7ngNOPkn9iL+ZDf2ruun6Vn8HCBiwP9tjV582tnf6Z3YhePRzaOdPYmlLEod7Z
         jAY1pF9Z1FbBi8yLWmMoxc8lY/FAfxsfBvfbOsJnxdkO7UV3QUC2g9itDC7YWPFkBLKf
         mhGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id p4si30711pjo.1.2020.10.22.22.02.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Oct 2020 22:02:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
IronPort-SDR: AvwFuSa30a7ULD2Nk8q+uGatPdz5Sdea0AWSMMWP8+P2+jTslTmju6BuMu3iWaXPkfUKvRJWfI
 Y1fzzWp3dTeA==
X-IronPort-AV: E=McAfee;i="6000,8403,9782"; a="146921184"
X-IronPort-AV: E=Sophos;i="5.77,404,1596524400"; 
   d="scan'208";a="146921184"
X-Amp-Result: SKIPPED(no attachment in message)
X-Amp-File-Uploaded: False
Received: from orsmga004.jf.intel.com ([10.7.209.38])
  by fmsmga106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 Oct 2020 22:02:15 -0700
IronPort-SDR: 7Day5D5KPL2/noKOCrxgfsCyMurAxXkzfTj5J0GV0BS3bePPACh7pdn5rGhilSEUDVqYQNYw7j
 kzNa5DgChLHA==
X-IronPort-AV: E=Sophos;i="5.77,404,1596524400"; 
   d="scan'208";a="466940929"
Received: from sjchrist-coffee.jf.intel.com (HELO linux.intel.com) ([10.54.74.160])
  by orsmga004-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 22 Oct 2020 22:02:15 -0700
Date: Thu, 22 Oct 2020 22:02:14 -0700
From: Sean Christopherson <sean.j.christopherson@intel.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Daniel =?iso-8859-1?Q?D=EDaz?= <daniel.diaz@linaro.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	"Matthew Wilcox (Oracle)" <willy@infradead.org>,
	zenglg.jy@cn.fujitsu.com,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	lkft-triage@lists.linaro.org,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-mm <linux-mm@kvack.org>,
	linux-m68k <linux-m68k@lists.linux-m68k.org>,
	Linux-Next Mailing List <linux-next@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Christian Brauner <christian.brauner@ubuntu.com>,
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>,
	Al Viro <viro@zeniv.linux.org.uk>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in
 libc-2.27.so[7f3d77058000+1aa000]
Message-ID: <20201023050214.GG23681@linux.intel.com>
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
 <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Original-Sender: sean.j.christopherson@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sean.j.christopherson@intel.com designates
 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Oct 22, 2020 at 08:05:05PM -0700, Linus Torvalds wrote:
> On Thu, Oct 22, 2020 at 6:36 PM Daniel D=C3=ADaz <daniel.diaz@linaro.org>=
 wrote:
> >
> > The kernel Naresh originally referred to is here:
> >   https://builds.tuxbuild.com/SCI7Xyjb7V2NbfQ2lbKBZw/
>=20
> Thanks.
>=20
> And when I started looking at it, I realized that my original idea
> ("just look for __put_user_nocheck_X calls, there aren't so many of
> those") was garbage, and that I was just being stupid.
>=20
> Yes, the commit that broke was about __put_user(), but in order to not
> duplicate all the code, it re-used the regular put_user()
> infrastructure, and so all the normal put_user() calls are potential
> problem spots too if this is about the compiler interaction with KASAN
> and the asm changes.
>=20
> So it's not just a couple of special cases to look at, it's all the
> normal cases too.
>=20
> Ok, back to the drawing board, but I think reverting it is probably
> the right thing to do if I can't think of something smart.
>=20
> That said, since you see this on x86-64, where the whole ugly trick with =
that
>=20
>    register asm("%"_ASM_AX)
>=20
> is unnecessary (because the 8-byte case is still just a single
> register, no %eax:%edx games needed), it would be interesting to hear
> if the attached patch fixes it. That would confirm that the problem
> really is due to some register allocation issue interaction (or,
> alternatively, it would tell me that there's something else going on).

I haven't reproduced the crash, but I did find a smoking gun that confirms =
the
"register shenanigans are evil shenanigans" theory.  I ran into a similar t=
hing
recently where a seemingly innocuous line of code after loading a value int=
o a
register variable wreaked havoc because it clobbered the input register.

This put_user() in schedule_tail():

   if (current->set_child_tid)
           put_user(task_pid_vnr(current), current->set_child_tid);

generates the following assembly with KASAN out-of-line:

   0xffffffff810dccc9 <+73>: xor    %edx,%edx
   0xffffffff810dcccb <+75>: xor    %esi,%esi
   0xffffffff810dcccd <+77>: mov    %rbp,%rdi
   0xffffffff810dccd0 <+80>: callq  0xffffffff810bf5e0 <__task_pid_nr_ns>
   0xffffffff810dccd5 <+85>: mov    %r12,%rdi
   0xffffffff810dccd8 <+88>: callq  0xffffffff81388c60 <__asan_load8>
   0xffffffff810dccdd <+93>: mov    0x590(%rbp),%rcx
   0xffffffff810dcce4 <+100>: callq  0xffffffff817708a0 <__put_user_4>
   0xffffffff810dcce9 <+105>: pop    %rbx
   0xffffffff810dccea <+106>: pop    %rbp
   0xffffffff810dcceb <+107>: pop    %r12

__task_pid_nr_ns() returns the pid in %rax, which gets clobbered by
__asan_load8()'s check on current for the current->set_child_tid dereferenc=
e.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201023050214.GG23681%40linux.intel.com.
