Return-Path: <kasan-dev+bncBCDZ3R7OWMMRB24E4KBQMGQESB3CUSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 08F003611CD
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Apr 2021 20:14:04 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id t14-20020a5d6a4e0000b029010277dcae0fsf3103542wrw.22
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Apr 2021 11:14:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618510443; cv=pass;
        d=google.com; s=arc-20160816;
        b=euHikG1Tlu4S+ObWU+c5cT6d4T8QiduFrqFDzj0NMe8uWSwM3M3OYUQG3StI3h3pSW
         quHopNVFR02V96Xp4RfV1cWP6m/bYhfa5gCcQ1KAFqpcTYz7kbjRXmqDlAbE/KPVLLAI
         jHtTEsDf5G0tpSZoloepBBonvI2RUwr18w7bvX7vRLXYfvg/Aa6unrtBjHX8uXAaKz6l
         x9nrWhVp76tj94oIeISGJ4bxTg7Ty5VOBFSep+m58OTF6V5+vpGpeHWNwGcwYHAGdj33
         3aaw4d1N4ECVdSr50JbCrGnDPH/qMJ+o/jOfVLK/e8XmNAcpzOOLbvA6omewpowsh0eP
         LnTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=TLK8cTVusNdmEdraCxtgE330Hk7gb/eMtFNpsdLZSz8=;
        b=uCabkcjw169bv7BLwSMy1p7cXqokTd14S0DWqbbHLVKDwFe8RmFU6sPSbMcekT4MsD
         cAtXR2F9gEU+H+W5wFGyzr3MPBNEaNAZxCJqbs7sBDv1qk7/vEG23qIOO9Nn0YL+HroE
         8C5y/G/nAjhc+kSdT3jxipV4zpp5lhriA4egZOoq50idC9sDVBsdBMCcjXcNJV99mlez
         mP5CuRiKQbWnd/9oMUCtDo0mnlQrpuICaJFZJf7leLcU2wPj0Km/9PpBc5iaRsJyna09
         iLJJAXABODRscWEIYEx5pUkrM3UDA9/SY88tK5kdDpvWpDl82Sh2Na6kosu7SyyCyCGQ
         O29w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=Te1Ium80;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TLK8cTVusNdmEdraCxtgE330Hk7gb/eMtFNpsdLZSz8=;
        b=N4m3qqA2ABLFJ+1orVOsfW2BmjF56aIdY2KjJ2r/iLwePZV7SGQhDySlxyxkC3B+Ei
         qlRqxPLi23E/ELhPPbngwKl0357XK4v0OPYsxVT+A1JH6Uucse0Km7T+vuU0KdjggQoM
         nIHeV2T94gG/NEj0CdqGzGYHshvltUlhgZKVc3uEuDk3Q2Ms2bqTy4UB1mEyTT0j3nkw
         NLbEP+K8L9CKaXXe7a7VRrOwVUZMEUQFp1CYXFpzoNnMLdhW89XYykgbL4TlP/V1UZ8P
         8Od0ob96vieWJ374/AfETRi7WohL/9SSVnLaJFONn+tElnOHHTsSwMk41EbxmTYB2yK/
         htwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TLK8cTVusNdmEdraCxtgE330Hk7gb/eMtFNpsdLZSz8=;
        b=VCjr88KqJM+Ivq9QH4PqrK2eO9Zfqgr+/2ZTEaUhMoawNf6gYMt52WrPqwZRKQhvtY
         nuzeNzw+GVVSSLtdTyo3xxslgKwEW1qc/7rK0Dq7HgXvjCKK28qevNaqDg4tM9gFFtNo
         Kl1HgHuN+JpC8EdFjJu5aWmNM/9v70S9KvAyeKpgPWIjZYPa7rgpK4QOOJa4VVCgbarl
         urE3uYkKRZ0gi3GX1bg6/F1nT/pyj/Bw5U+cze6qYNF11tJneyNDdTVrHYIMKxHqM/6b
         wIQmpxrdWnMV+5K0Qul/lrg/IRmUEw6wpbAqxFiebiW+s8wud7M1iJPwUnlsmR/kalLf
         hAuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331Sdux2whgH/K1hgDFHyxxwUSfOw4Gr9lW3bRUmePYbjgQkSDN
	Sd0eTAQfhGQVrrMyT26dWQo=
X-Google-Smtp-Source: ABdhPJxn4P7hEqo/dSzbuLv5kAawe2DfgB6pkv5zPz+kT4ny7RRbJduDYgb3b+mwQGhq8GuDdzVp/g==
X-Received: by 2002:adf:97d6:: with SMTP id t22mr4882538wrb.123.1618510443780;
        Thu, 15 Apr 2021 11:14:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6c6a:: with SMTP id r10ls2895336wrz.0.gmail; Thu, 15 Apr
 2021 11:14:03 -0700 (PDT)
X-Received: by 2002:a5d:4083:: with SMTP id o3mr4821137wrp.397.1618510442942;
        Thu, 15 Apr 2021 11:14:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618510442; cv=none;
        d=google.com; s=arc-20160816;
        b=NKQ2IMY2Zit5AvgAUkrU8ttcOvk+lHh2eL6bB6oHdQALb/ZmoOQi0K4iw3E1cnKGtQ
         TNYNqOiXGgvFU5U5jTWPHHQdRp+nGn9n2YaRCfxKLwLRkSlILki9dqx99DmmlNC1Dz66
         J77yDlrtSifCWE+f/9gEuTdtpWhsGE0mJilnIHtqFBzkn+8UzL0bWW8zAbQ0HUmGQv+w
         +WCsg7qCyJhaVNJjtSQrx93fZ8FDREcyTP8iciij70vwaWygckfoqHU+xC+7/AlLbz/U
         7ky6XRvcBzYh6o4M3oGsuiwhFbTvMniMuR7MvxKH5ERAMYUCPu88uBReR2JK7Z9ohpN8
         oJDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=aUvcOQRHCp+PKZyZxQ0oh1HFQbFdGaAS6RVsrD9rkGc=;
        b=RS1zALVWDRd9eLVnIVSe6v6tfsNXaA69WGSf1po1LTRtLSVzn5r8RajFyU8vNvW7ly
         hezyxV5w0JdPg5UfwzgNa35vtxTtHw4tO4CyJ2H/cDuqx6k0KPB0xZOPxDBJERKBESKj
         RWRDdd3uF3dvj957c0Uok4KuNrTXH0GJzn0QhID7V0STf6hEZa/iP9niOMw9zb9R5ZH1
         XcKQHEqO2OqA2rrR+46+tJ/1JEcrgXwFkja0ka5WCOAzPYBUbGbZQA1/zLScLJOoImWh
         dQVA7FqOptwHFIb38dACQYZyZhPgt4Rqkezb1HIXHOjZRmgoNpHZcwZ45OQR1r3nyZ5K
         8dwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=Te1Ium80;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.15])
        by gmr-mx.google.com with ESMTPS id x16si182762wmi.1.2021.04.15.11.14.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Apr 2021 11:14:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted sender) client-ip=212.227.15.15;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([185.221.149.95]) by mail.gmx.net (mrgmx005
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1MryT9-1luOgs1hXJ-00o03y; Thu, 15
 Apr 2021 20:13:59 +0200
Message-ID: <f2f54eccdbda3bd09eee8bf50264133faf84b80f.camel@gmx.de>
Subject: Re: Question on KASAN calltrace record in RT
From: Mike Galbraith <efault@gmx.de>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Zhang, Qiang" <Qiang.Zhang@windriver.com>, Andrew Halaney
	 <ahalaney@redhat.com>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"ryabinin.a.a@gmail.com"
	 <ryabinin.a.a@gmail.com>, "akpm@linux-foundation.org"
	 <akpm@linux-foundation.org>, "linux-kernel@vger.kernel.org"
	 <linux-kernel@vger.kernel.org>, "kasan-dev@googlegroups.com"
	 <kasan-dev@googlegroups.com>
Date: Thu, 15 Apr 2021 20:13:58 +0200
In-Reply-To: <CACT4Y+bVkBscD+Ggp6oQm3LbyiMVmwaaX20fQJLHobg6_z4VzQ@mail.gmail.com>
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
	 <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>
	 <182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
	 <CACT4Y+bVkBscD+Ggp6oQm3LbyiMVmwaaX20fQJLHobg6_z4VzQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.4
MIME-Version: 1.0
X-Provags-ID: V03:K1:WJcUOFmUdF8mB3VJ5X9eU2m+Rl2Ob9KE5WzQ1EJoxEPmBschOWJ
 G0uUzYiIaxZhzPeEobnkLMfaC2Dyjb35GC+MF+ZIuCSlbmFyQEag6qChD0u2eMxfMtQz9Sm
 4ZH1WO3pB7TeCcbAOQrel7mENL1yYyyqrV4pQGNRZ2Fpzkd4LOSWQSoZ28rCIHzOw/jKKpI
 ROpl1fmnZNsZPaRE1Cprw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:rKMJVeirOr8=:t/2IQteopQzsoMRImFcrCA
 axURKvimsAVhEWifQy0R59n1E/FeSERO91LhNZFzBNaQK6D0UMdpy31T25j95P3QyWAUfj0Qg
 bbueTBPleQAnX0I8608aeTAb3z41Gau+QgGNP8Pg2oVyHMT2LF2lU1rI6Xv/gxsNUJIYZoWob
 chPgbTI08blR5xmzrwHP5z5LKn5dgl2G7WXqu5dP19iBSe9RIx8uuUDNzV3pvyIv3DLq2qq6N
 wr1MoKgGooJWIvA7vNwPrvjRsXkh4udLHoijWqnm/ooXLGY7EZJAN7zyT9y0dAO9w45CrBjsT
 HfaBEyh0KtzZktsR1Fq7H3QA+bcN7KyOMjgg7HuXvWT9X+YG950mYQTf+MUfPFwuoRsrKmUaD
 XLtZ9nLp0C5AR9ZzdCVNB0nUBBEcGJiTKnPBrhrtAJlrdS6Cd3Tai1Y8BpxB9QRCXn1CsBTC1
 FVDaT/SqZmZyvpY7QLHn7YCacxd7cj/ft/zMfv+Ynq7Kpirzrj/s5lkl5W2a1abjjlrGmzomU
 qBD6KePakNsNQ+r2m2tRtdzPa/D9hUbzw1thVgzWQuCVXooPQ7kp3V2jqkOGRprUWcu8q/Rf1
 VHkQnuZ6VyxL/UV9pOluLWvtzD1FHBaYNdvwdj6foziTV2lc2Gq2xX034/0QRZKt1mXgyE987
 hibyAF6Y6LIdp8jHrsxRnVfFZ6hTsbZfnGRi2ztZpnyF4JG5eUKdsERKL5yOV9aqDNp9tKd1y
 dNmvVEQsHdOowMHpj2f819m3FZXhCQyQcwaEH0HZHkoUwPvwsfLKMzGtdFirg+qrNLmi3NWGm
 4kH79ZpZJNK4OvOoB4/HFTjGsUOTi8KkWsgrJ8HfhVSXlCErRdB03xXwtd9MePu/Anbw8v0t2
 k+VrBNzkQzL9/ncUATWTUjABbqXJZVftT2nLBwoANrluj4s4WFZxG29ARUjH3exYNPsiuiT0h
 pNtJjhOWA+NaCjMums2AZmi0bBMEvSiiltP5jdOaVkafDkIqosylf9THjNKliWuSdeDgSa5uW
 gsw3hiinK6Ns92hO6Up7s9nPq9qWUALQMPT3b+gSCQR+1mUMe1y6SzgvyFoqq6W8ALEUlA7u2
 m7DuDSSQGAOoAac7jEYZBEXxMbNsQhElD4NrfzHrJBGqi/FNuUVHd5Z4483vWTIW9RZGNqPAV
 2Rj76HAO7MXISUGihgteaU22mzcy57SfYZ28ELhN3OGJYY+6BQdCNUQSRQ6In4LI3KsfE=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=Te1Ium80;       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.15.15 as permitted
 sender) smtp.mailfrom=efault@gmx.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gmx.de
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

On Wed, 2021-04-14 at 07:26 +0200, Dmitry Vyukov wrote:
>
> > [   15.428008] ==================================================================
> > [   15.428011] BUG: KASAN: vmalloc-out-of-bounds in crash_setup_memmap_entries+0x17e/0x3a0
>
> This looks like a genuine kernel bug on first glance. I think it needs
> to be fixed rather than ignored.

I posted a fix, so KASAN earns another notch in its pistol grips.

	-Mike

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f2f54eccdbda3bd09eee8bf50264133faf84b80f.camel%40gmx.de.
