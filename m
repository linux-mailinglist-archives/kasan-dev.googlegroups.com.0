Return-Path: <kasan-dev+bncBDW2JDUY5AORBMPNTWIQMGQEF3JVELY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B7284D1BBC
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Mar 2022 16:31:00 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id l4-20020a0cc204000000b00435ac16d67csf1821091qvh.12
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 07:31:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646753458; cv=pass;
        d=google.com; s=arc-20160816;
        b=z/DJ78pVizt30TZBGg2Bt/GSNBVSnjKYK8MCWYB8yDXgXarWtea48WrohQNIMOzsor
         Vkqc9rrcard468ApN4RKDk+Eot/boufFH4sDa1UiUe28iaI6lAyOqi2lMFCKZam0PcPj
         26y/RBSizGW9l89FZPuO59cTQd8geJOvZmeNCVNVe3MpayQvR5cc+xcoCKNSzus4jwrt
         fT66tqR5UB8MeDoKj+og8E8h2RkJjMX6b/G98GkOWtqOoEJKKMfSDC07GPv3TwdtzK2v
         ieZT2UiX9UcDfHa1j0bWCYhkdXbIU0/dZi+AC6fumgVOGOSF0bAi3b5WDZb0mzq6GfSm
         gAnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=5egmLyxKBgBbcl53ek+0FL5NmKhSz2RCTgDCkt+NrRo=;
        b=S4/i/JsSRH6yAOrX19uuS6j1pV8ElptQSr/UCTC1LI0v3TJ8mbN4rgP+DJAes9f44+
         cCYIqlxTHmNDwlhwOePxxB/PdJYO5Z8+J7Tt3jnT0sZKivZm1yYaSUpuulgR8oK+7cO0
         khfwiiQQvE8BMcLG7XD1hMryZ/1nljmEMBAL8jhCRm3YcOHohp2rMcQc1Kz+zYKTVPGI
         oGFYwhP5qdJwY8zi+ABRk9LT8LrQ6INW5pAbrnyZYwjRLmTgEIDo+iWiQ3Y6GFDCGPJU
         eZzaVdAczbNUZkBqbeHmpfYnSpJmyy6PWnxZ6Nu8CHslGq3xMMbxYaxjSv5bUwUT92wl
         bLJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I68j85a6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5egmLyxKBgBbcl53ek+0FL5NmKhSz2RCTgDCkt+NrRo=;
        b=ORYTL7QUpGR8srd+ASmZgG30AqhYdU1j6wlABpS0jdhLVMCJa+cPHnC+KvpPfoDJCj
         uod+p/kVAlXARcXqfdgfDUBVnJXIxuDuAneS0hRo1gA6nso8D0mTLM1BsaOlHhwwYwuC
         OQFKG84ezE2mIWAH9TaCi2lMTfUWvYT48aJeBy1kb+Cm19vV5IWP0rJttJeZEX9YQjkM
         xQK6KOeEPkSSdZhPNrvYeo9tEKnVg1GyxVTZg0F+sGKzvhZL0IWyiXlWVCaPCVCNfqL1
         NrqeXOZ+JWep+W8tyOtT9iwQqbQFe1fiDCYmbsVxUN/oXB8Fp9e1Xwt1eW4xf4JupwtW
         1AMw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5egmLyxKBgBbcl53ek+0FL5NmKhSz2RCTgDCkt+NrRo=;
        b=XKzqtuWLo/UL2SyY2apEvKig1xyvMqN1MKupgwpMDv942ZQMBU3GmBqwlMM9VSxE/B
         xte7WuSvlK7/FUK6iyu0UOdS++3jtrzoNX3fmjtE6popk3czj9gOwa9QImX3Hmp3zkk7
         8MdY318kWFJVMu4U3Xi3S5iIl+eCJcDK6sDNdPELRdnMRXrDT9xn4SodIHmtHAHKE7pl
         DOyLNIOHbluHAqomoViBmhlcScmoxzrs5K0dSTHlg6ywA7VdbNs350kkseEFJopesAX4
         hcIOZDR3pU/j+5rltn+FbPmLnKKkJXG/b6Ypc1KD7eZT4koaPa8URjd5BEEeAN4YKW2L
         ph/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5egmLyxKBgBbcl53ek+0FL5NmKhSz2RCTgDCkt+NrRo=;
        b=7nd31zP2dATpF0A0X7vJl9AKH8jBa8ciamQX0+szrANaxuInq85Xj61aOEHXL3qDnX
         ub+n0r+fKhdl0nIocFOdX9N+rjxf3PsowxnYH96bEywkRRvs06Xk8twT9QSdJrLEzAeY
         dxO/MtOI1qsseelG3VROwODXKTCDnjf+WvtFOL5ViMASs4ge7yDFu3tYux5VK9b/mFYu
         rufhWkSSd75FEk0weJP+zpTXSE07Jz75t7hDSbBHZFkzG7yaCik0tYCmY6lBl0OnshBS
         aMV3cjtepjHCym5L2nOIc5EoB8yqq9XGQ3m4yfZZTRu7r0BAlqh4cRCy1bCR6cuElInj
         dz9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JutSOPN9pG5NlLqh54+++WwHHSuIdBgl+F4VS4RAkJxRH1qF5
	GYIECkfpfdoKXSUerZzYyU0=
X-Google-Smtp-Source: ABdhPJz4g1OdbUdUdO9QDpca8DDhUf4kh3svKa/zHlSCqJxBonTkZTZQRUxer+u+jeBNao6Bb8SrHg==
X-Received: by 2002:a37:9c02:0:b0:67b:e70:5e70 with SMTP id f2-20020a379c02000000b0067b0e705e70mr8972116qke.778.1646753458066;
        Tue, 08 Mar 2022 07:30:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:18a8:b0:2d6:8498:2287 with SMTP id
 v40-20020a05622a18a800b002d684982287ls10218035qtc.10.gmail; Tue, 08 Mar 2022
 07:30:57 -0800 (PST)
X-Received: by 2002:a05:622a:134a:b0:2e0:76db:b939 with SMTP id w10-20020a05622a134a00b002e076dbb939mr1548094qtk.311.1646753457546;
        Tue, 08 Mar 2022 07:30:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646753457; cv=none;
        d=google.com; s=arc-20160816;
        b=RPJmQ5/CAEqVwYcBKEZeNf0ZNBetP8f8KqQ446flQ5bJ8VTOynoMqYOy3WXgGOLqgJ
         tnPrucTzfpyKaEKw06EqiWZh5AN6HT+/eTejhY4ieLnB/Ony0Kl/29aC3A6dA5DnlYfd
         nxs+ej9dNueSl7vzDZruAEyj6XDqrwnlxS7TeBOPdAPaYALDvn+WvO9mrz7rI7TQVW/2
         y4EhDcGkrYMoat9Ad+U0f0ppi2k14IaerdxFXuVaJ7mjnM8cgBwx7StN/iUkwGMAp5DI
         FMkYiewyCmZ78Qnbblh3M1SvgCxyKQMsqDxoPfpZxDfugNKd7kiLV4hFZlNDKrVVvZm1
         IPgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QL+ZtmXXGFLuTx2y9WXZomB2eATV+ikv3E06Gw8vFq0=;
        b=S042TZLazgeIwedEMGoeo644X1gOIyLaK1FRwYU6GLerSQT7cRl7IiLXija2DTzWpB
         0oNF/DiJwUtP3esf4EdNXxV1IP2NBHfKQrz/3I0Sll8kKN8AJsQ+N191kdcPfRLU3cSk
         Oq7DbBhe+KL4wIIO4HsDiWvrG4m/+CD1tal8NQqLIZOJg61TH8WessPhBV7kPuntKv/Y
         0cjfzODOJER91TiZEnbFn8PjETiccNOxslrKi0zvVPUtKBAPn/v6I3G91CpYjJgPavzN
         RnvDB3+1tZJDubGIEjR5deAfdAt1G8TmU6FRPmNNwOHJBM1TAZ++5DZl5ee+gGb07Yxe
         96Lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I68j85a6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x133.google.com (mail-il1-x133.google.com. [2607:f8b0:4864:20::133])
        by gmr-mx.google.com with ESMTPS id t7-20020ac87387000000b002e06b63a5dbsi332359qtp.2.2022.03.08.07.30.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 07:30:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133 as permitted sender) client-ip=2607:f8b0:4864:20::133;
Received: by mail-il1-x133.google.com with SMTP id p2so3922843ile.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 07:30:57 -0800 (PST)
X-Received: by 2002:a05:6e02:20c3:b0:2c2:9e23:8263 with SMTP id
 3-20020a056e0220c300b002c29e238263mr16510481ilq.248.1646753456934; Tue, 08
 Mar 2022 07:30:56 -0800 (PST)
MIME-Version: 1.0
References: <cover.1643047180.git.andreyknvl@google.com> <fbfd9939a4dc375923c9a5c6b9e7ab05c26b8c6b.1643047180.git.andreyknvl@google.com>
 <your-ad-here.call-01646752633-ext-6250@work.hours>
In-Reply-To: <your-ad-here.call-01646752633-ext-6250@work.hours>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 8 Mar 2022 16:30:46 +0100
Message-ID: <CA+fCnZdCZ92BxnympNoRP8+3_gGDMZQgTeaUpga3ctuRq8zPYg@mail.gmail.com>
Subject: Re: [PATCH v6 31/39] kasan, vmalloc: only tag normal vmalloc allocations
To: Vasily Gorbik <gor@linux.ibm.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Ilya Leoshkevich <iii@linux.ibm.com>
Content-Type: multipart/mixed; boundary="000000000000d579e505d9b6aa3d"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=I68j85a6;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::133
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000d579e505d9b6aa3d
Content-Type: text/plain; charset="UTF-8"

On Tue, Mar 8, 2022 at 4:17 PM Vasily Gorbik <gor@linux.ibm.com> wrote:
>
> On Mon, Jan 24, 2022 at 07:05:05PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > The kernel can use to allocate executable memory. The only supported way
> > to do that is via __vmalloc_node_range() with the executable bit set in
> > the prot argument. (vmap() resets the bit via pgprot_nx()).
> >
> > Once tag-based KASAN modes start tagging vmalloc allocations, executing
> > code from such allocations will lead to the PC register getting a tag,
> > which is not tolerated by the kernel.
> >
> > Only tag the allocations for normal kernel pages.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> This breaks s390 and produce huge amount of false positives.
> I haven't been testing linux-next with KASAN for while, now tried it with
> next-20220308 and bisected false positives to this commit.
>
> Any idea what is going wrong here?

Hi Vasily,

Could you try the attached fix?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdCZ92BxnympNoRP8%2B3_gGDMZQgTeaUpga3ctuRq8zPYg%40mail.gmail.com.

--000000000000d579e505d9b6aa3d
Content-Type: application/octet-stream; name="s390-kasan-vmalloc.fix"
Content-Disposition: attachment; filename="s390-kasan-vmalloc.fix"
Content-Transfer-Encoding: base64
Content-ID: <f_l0iafuk20>
X-Attachment-Id: f_l0iafuk20

ZGlmZiAtLWdpdCBhL21tL2thc2FuL3NoYWRvdy5jIGIvbW0va2FzYW4vc2hhZG93LmMKaW5kZXgg
NzI3MmUyNDhkYjg3Li42OTM5NTRmNzcxZWMgMTAwNjQ0Ci0tLSBhL21tL2thc2FuL3NoYWRvdy5j
CisrKyBiL21tL2thc2FuL3NoYWRvdy5jCkBAIC00OTIsNyArNDkyLDggQEAgdm9pZCAqX19rYXNh
bl91bnBvaXNvbl92bWFsbG9jKGNvbnN0IHZvaWQgKnN0YXJ0LCB1bnNpZ25lZCBsb25nIHNpemUs
CiAJICogRG9uJ3QgdGFnIGV4ZWN1dGFibGUgbWVtb3J5LgogCSAqIFRoZSBrZXJuZWwgZG9lc24n
dCB0b2xlcmF0ZSBoYXZpbmcgdGhlIFBDIHJlZ2lzdGVyIHRhZ2dlZC4KIAkgKi8KLQlpZiAoIShm
bGFncyAmIEtBU0FOX1ZNQUxMT0NfUFJPVF9OT1JNQUwpKQorCWlmIChJU19FTkFCTEVEKENPTkZJ
R19LQVNBTl9TV19UQUdTKSAmJgorCSAgICAhKGZsYWdzICYgS0FTQU5fVk1BTExPQ19QUk9UX05P
Uk1BTCkpCiAJCXJldHVybiAodm9pZCAqKXN0YXJ0OwogCiAJc3RhcnQgPSBzZXRfdGFnKHN0YXJ0
LCBrYXNhbl9yYW5kb21fdGFnKCkpOwo=
--000000000000d579e505d9b6aa3d--
