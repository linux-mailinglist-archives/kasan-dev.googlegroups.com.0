Return-Path: <kasan-dev+bncBD4LX4523YGBBB7MRGBAMGQEVOIHMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DD8632F241
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 19:18:48 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id v6sf3340836ybk.9
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 10:18:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614968327; cv=pass;
        d=google.com; s=arc-20160816;
        b=IlrcbCeJgkGY/xwFj0FAjWg7/N3uGi9lNCTZ1lcipRsBgc3DZ9Wakd0yJjFbrEUKTX
         WrtYA7EEuunvo5SdpQ4B2G9PaKWsHat25sjZSEZnRlO/aw0er6AkeFdIQEHQaF7g3C6k
         5x7pLQHOA3dNfivkhY/pUecG/rK0yaIfiXu5l6OOXQ62ac+x+ftdoGtwhBH9aL1MfDQj
         ICBWOLjPL1aLgFG/2MUf6X8onRaTohppJNe/oyku7KIWKe5+890OXRchhqD7L2z4m/fq
         h159VjeL8uh8UAYgXmy3m9y5kXKBXrEzIVsjwFrEgLTNQEOFYyXV+e88oQv0AGkXayS9
         3PyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=wzCvlzBrzLB5C4F7QfaRLH5xAOIwK2yYks8c5gI2yAs=;
        b=U2PUw0W+fgUkwm8DXwzKYUULa7rUIRfxS8eZW2XvLXjTf5sVSOcSfp1EG4Ti7OFHnH
         q2K/mvVyUDZkcaft9GCxeahBwXqGX6ar6MBl39C1AJ9aFW8HPdeUu15sc/wLnWXCSbtM
         Zput2/YF7ttALvCgnztiTyrqF9eZD3Qa0EaANo1b9iWNapUX5k0FyWtm0oFuX08bVW+t
         QHHaG/MwiYaNnmbvJTW+jISeJpSaSrwOIh0MK2j7zw2RMIX2ejz5MOWenNn927OsA30K
         0dwz+6fc6jjZuQwH+cDw/kC/scVZth8fyCEElH/c38SZtqgq9yntLE9kUADKwuysPyU5
         7l6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wzCvlzBrzLB5C4F7QfaRLH5xAOIwK2yYks8c5gI2yAs=;
        b=tF33sAn8isqB7sNmNNJoz9f6ndUQ7GRY8+0bVb8CdHqBR0cwX6ToOHRzqiYi816TFa
         3nkolRhst0Ujw/sfcLdTkv8AanzaSp5GL4t81CM5u78QPgw9i3/nbBjyb5K6mD79M3O0
         xAmY59KhmL6HzG0mQi8kiD6dkIS/M6QFnXYErBpy9ftQkCu9fz4XH3rlwi7RrRGgKOtE
         P23lSzGW68pu8DVjVa3uiQ3Mvbj8MeXyHKPbiPyCGQy4smkp4GsXkzELI1Lxveuk4o8v
         dWJyvtEBs2BWhJVDIii9lVwFxDRrh1NmDZF/HPcF0F7VdmLIaJUxToqMhzD45QyUmO2b
         Qf3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wzCvlzBrzLB5C4F7QfaRLH5xAOIwK2yYks8c5gI2yAs=;
        b=CSgAiXPC3Z6CdZrIbISv4t4zfimQpeuY7evClChPLQff3F/OY1+DFD0Bg1ip51wgFe
         fzvGHb8r+1JpODGBmnBtFsVUMQhG28iJb9NE46e4wdrN6NTO1I9NMN0cy0N1t78NMwA4
         ONShKaW9utd8YVxUwRtx8UnU7oFQ8YNPBsgZ1eTkEswu1gHpYIOZrEPvfaTtB8E52cau
         bZGAkgYk9qiRuY41FeZ+1o6BiFG3adTppaoWJB0XpDIgt/sfrrPlpFupfm9qZtE+iI5u
         YRFG+DokhpPXpsid/ZuPjsMJnqIyf+wo6jqhwHwqyaXNFVSFmf9EWClt2+cMU+5Yf1S4
         jcEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531DgwEDL0zfwEokOqiDRkZqrtoptgBtwt7kRb0QUTfYPKu7AI9U
	z5XlrfxOYIoQ4qgUJ++ywSY=
X-Google-Smtp-Source: ABdhPJyArYtkohA/QIGoTgLdpDA/rQrHVwaeVt6B+TMKbPb1ps8kORwYcu0txp632OIAh8TTtBGTaQ==
X-Received: by 2002:a25:eb02:: with SMTP id d2mr16422815ybs.250.1614968327281;
        Fri, 05 Mar 2021 10:18:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:77c7:: with SMTP id s190ls5053092ybc.1.gmail; Fri, 05
 Mar 2021 10:18:46 -0800 (PST)
X-Received: by 2002:a25:4ac2:: with SMTP id x185mr15570190yba.326.1614968326733;
        Fri, 05 Mar 2021 10:18:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614968326; cv=none;
        d=google.com; s=arc-20160816;
        b=RY2M80NRYrFpZ+ig9x8F6uvArqKXFkxrc6CaI7mFSuFFhKG1Ub3SplT+wc9cXDMRh3
         M6jGPpgrWpperXxpcvNH/y7652JUqU/fXI3C9mZj7XUmiYWBwDS0pvKBQK9cVr5RtpGh
         bEuugV/CSc1fTyLVUlCSb2Yl0Tf1mDvB/ob7H+Zr9ZthGt5eg5PO8YEp4+oc5ee8fKTT
         wJ5niaYrnfTWZuS5RsqXAlcjXnXVXP0IEoxq5/KFM8ouneEsFU+/sbtjN/Fi0IoP/sV6
         yR50Pvdc6yzPJi70A2GjUaEXE7hKZbeAkTpp5PBJltnk8JaARgOBogyOzdD0WoetGHMO
         WuRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=uBlulfvmmPFGGJlTfNHZSuH5ds7nmATJdLUXenr/aOI=;
        b=MJRDzPeNODX1A+y9H6XArXnEb8uqiAQCsiyDtaUFz3kev4VfzVllcdwM9GCnBEqnTh
         Tm0uJvSAlN+yv0biIKNSTWT20Dp60KMJIGNuRBV0CCm8jkrv8/V5MXaE2D7FmhyHi25N
         cYPEyXeOjtZvCDoKZbskcCc6Rx365CfLGFardxubXkhYZel/6Qz61qvhiE4GbJ6J3Up2
         /pTFpkBECezNUofTZ/vi72L6SMMwtHE7s+QcIDJH3IqZRfhqlf8nSekRBFODmxWjG1Jf
         ACIZVNuxfqn7E8+kT4kc3b9hWSPPQBcG0QWVR7e0kDcyRsVCEcmHeKAzn/tbZ1SliiSm
         tsow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id x23si178398ybd.1.2021.03.05.10.18.46
        for <kasan-dev@googlegroups.com>;
        Fri, 05 Mar 2021 10:18:46 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 125IGTa8026099;
	Fri, 5 Mar 2021 12:16:29 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 125IGS7W026098;
	Fri, 5 Mar 2021 12:16:28 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Fri, 5 Mar 2021 12:16:28 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Nick Desaulniers <ndesaulniers@google.com>,
        Mark Rutland <mark.rutland@arm.com>, Marco Elver <elver@google.com>,
        Catalin Marinas <catalin.marinas@arm.com>,
        linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
        LKML <linux-kernel@vger.kernel.org>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Mark Brown <broonie@kernel.org>, Paul Mackerras <paulus@samba.org>,
        linux-toolchains@vger.kernel.org, Will Deacon <will@kernel.org>,
        Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in save_stack_trace() and friends
Message-ID: <20210305181628.GW29191@gate.crashing.org>
References: <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com> <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com> <20210304145730.GC54534@C02TD0UTHF1T.local> <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com> <20210304165923.GA60457@C02TD0UTHF1T.local> <YEEYDSJeLPvqRAHZ@elver.google.com> <CAKwvOd=wBArMwvtDC8zV-QjQa5UuwWoxksQ8j+hUCZzbEAn+Fw@mail.gmail.com> <20210304192447.GT29191@gate.crashing.org> <ed3c08d2-04ba-217e-9924-28cab7750234@csgroup.eu>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ed3c08d2-04ba-217e-9924-28cab7750234@csgroup.eu>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Fri, Mar 05, 2021 at 07:38:25AM +0100, Christophe Leroy wrote:
> Le 04/03/2021 =C3=A0 20:24, Segher Boessenkool a =C3=A9crit=C2=A0:
> https://github.com/linuxppc/linux/commit/a9a3ed1eff36
>=20
> >
> >That is much heavier than needed (an mb()).  You can just put an empty
> >inline asm after a call before a return, and that call cannot be
> >optimised to a sibling call: (the end of a function is an implicit
> >return:)

> In the commit mentionned at the top, it is said:
>=20
> The next attempt to prevent compilers from tail-call optimizing
> the last function call cpu_startup_entry(), ... , was to add an empty=20
> asm("").
>=20
> This current solution was short and sweet, and reportedly, is supported
> by both compilers but we didn't get very far this time: future (LTO?)
> optimization passes could potentially eliminate this,

This is simply not true.  A volatile inline asm (like this is, all
asm without outputs are) is always run on the reel machine exactly like
on the abstract machine.  LTO can not eliminate it, not more than any
other optimisation can.  The compiler makes no assumption about the
constents of the template of an asm, empty or not.

If you are really scared the compiler violates the rules of GCC inline
asm and thinks it knows what "" means, you can write
  asm(";#");
(that is a comment on all supported archs).

> which leads us
> to the third attempt: having an actual memory barrier there which the
> compiler cannot ignore or move around etc.

Why would it not be allowed to delete this, and delete some other asm?

And the compiler *can* move around asm like this.  But the point is,
it has to stay in order with other side effects, so there cannot be a
sibling call here, the call has to remain: any call contains a sequence
point, so side effects cannot be reordered over it, so the call (being
before the asm) cannot be transformed to a tail call.


Segher

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210305181628.GW29191%40gate.crashing.org.
