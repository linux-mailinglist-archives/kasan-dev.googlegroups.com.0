Return-Path: <kasan-dev+bncBDB3VRMVXIPRBEXPWCFAMGQE3Q4T3TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C1E744159E1
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 10:15:14 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id x29-20020ac259dd000000b003f950c726e1sf5380740lfn.14
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 01:15:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632384914; cv=pass;
        d=google.com; s=arc-20160816;
        b=mRab9kR4/mBSjos9XLUGzRWmBwxm/CI1q6CFhcm+aFiwtTSgqTKXd4J3moRPO2NBPn
         k+CXgt8uVRb09C3meQazxGk96Fm7o8DThMKInl2ryQcA8z4UJvAYsqZ5FlQa9wW7kIzG
         F5DenfjMGOMkxGTg12owOCqGkG622lgGbAyfCKaCa2KD20OU1BIFjOGbcNjpc8dqYjgv
         t9BO01UwR29WT63Js0H0QVdzjw2aQLcvL+jzoPUdJJobkr1TouQ8+1q49dMJQRf0jIlQ
         8VdDXa/v6WAMvAnBWC1uiDl5hYfQ1ScMcXzy8oTnk/Z9ZGSQlVSQlSiV1c0aY12WQj8X
         37eA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=90FNa9Ow/OE0zX/iRPP0fOpt7WvISJE2e013OU9cNnE=;
        b=Ij5IaDhIF6+XhMxtKgZkLFL9tRcuqSH4bKrWDwhsO8jyplGy8AZG7yMFbTVcoBiVJV
         c9qdcykxAnBzk3Y+DyoPSvtxqSCUvtVB5k+n2FsiteyLoIt8FDH49Mi9fNVloKzdX+/i
         9UGZnTx1paqct1t/RwLJFlE4eBp9BwgfyxLV6YpKwYAtUiLCKuO0LgPaV4h+uPBgc0PD
         KfCawekykQQUdBbMkRsluiQNJY2MgIsKCCgnssS9Y7O0es/wGPmifWKCLJl5oKU+W9kD
         rAsZex5SAHZlhRsq4/6uKjkmLmFXRLNqddfq2r7l0Ns+8/gQ3d4OITsqnAv3/pw7GrGe
         vKsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=dQkZNFnV;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=90FNa9Ow/OE0zX/iRPP0fOpt7WvISJE2e013OU9cNnE=;
        b=JBo3AVXPvPDGRsmUXtOAEQo/l5RmcHqXuIbixZv1HWBYJwy/dHbyo6nbYyckUMiLR1
         gkRW/CCrTvCBp7XIiyQtrRjM8p1aIMst4LsMFq6Uh1z/j8ZMa3+segQCLJFJzMkgde78
         iFSEnOLcUgMW79h4hZhjIIzZvyZHh1f7Ngl6Ql7VxwSmkibIxEV+WJFOhFXPMOFMjuf1
         Jfe/74hi3HsdqlXSXZzXHKKcOfyobXOrFWPo7m4rEPbHvB57mP9Pk5gSsqwP7zGQE8Wo
         dxXkRU3ZrprZrfuGVlLC05npm1rAdWQHwMrpRCLPONdlWHvcrNeuedA/d9VVVpxNuqDa
         YItw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:subject:to:cc:references:from:message-id:date
         :user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=90FNa9Ow/OE0zX/iRPP0fOpt7WvISJE2e013OU9cNnE=;
        b=eMYuWziEq+67Ok1bw4/1OFWJXebRPl0tA6iNUZ4wDZhW5O+H6iK/qaB4JFc7MxrlwL
         9J44rRZQDzwbEwiTG1t59LKy3St4zjioV256e9+hS6rRWmasLkdzAgOeK2UndVhgIDRT
         eqmiqBzUMbSCA63PD5Sv4Oksi9SgZdCydGXb04mn9gPMsAjQdwtJz9PsxFrtSAImySUa
         0Fpf91AyXtRTvFwwVqJIa7enPOFvPsfYNBvQ9vRLUX5WWlzXA4rY0bfp7+j86LduDq03
         MMbRwOtZ08l0pc7vXqyUaDWblKHw4dDUFN+NWMH4vmcVu9uMrCfniSoEMq1l74cn+cpl
         Rnxg==
X-Gm-Message-State: AOAM530aVpHqVm3Dl1lnOhtLVOUbW/Cboig465RdmM7cs8ELlPIpKayR
	ZkkWsXekVicaeg+bdkBgvkw=
X-Google-Smtp-Source: ABdhPJxydUKzQrHieLdR2PpU8h3Ub47Nh2p9fQeDT8hBHg40feRa7kmto8OI5XfaMpCw34QkeqltUA==
X-Received: by 2002:a05:6512:21b:: with SMTP id a27mr3022654lfo.684.1632384914360;
        Thu, 23 Sep 2021 01:15:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3746:: with SMTP id a6ls661566lfs.3.gmail; Thu, 23
 Sep 2021 01:15:13 -0700 (PDT)
X-Received: by 2002:a05:6512:3982:: with SMTP id j2mr3054560lfu.332.1632384913340;
        Thu, 23 Sep 2021 01:15:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632384913; cv=none;
        d=google.com; s=arc-20160816;
        b=PnxleAm47rSNihEXoRP6d5EhSTU0B2vI0gP83u4U0pMMJ6EXx1lYlcEHw59KZp2h5T
         F3hZQq5aSOKBI9pl6kvvzRy+MW0RFuA4rrCn2uO7FigtqG1GygOY2Szeg2Owk0x6j2Ub
         GwJoufJhWwIffv3ZVe1Cd9+US3ZmL1xVNvVe0NIzrGzsVi8TGJyYhNWIwE3aAAR21/39
         Fkrpk01DnlO8rfnmtvAFkIVVwQZgI52+tlxoi/oZCElSDLZ/F+0hKMxjyCrH63gLmdA2
         AeY82hQ4jabW4yVbOFxY4WpZEUhoOHShfxM45D1sl39V92SRwXSEmXzng8uJR6didAdh
         l+0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:dkim-signature;
        bh=QSLhmvEk1Pq1iiswl5snzLhelQGabqOAvRi47xucKUc=;
        b=YQaGJLKx9CYq3pJIIHVXE1kIN1FGd7ixD9PDwrQk0p/ZonwqFFh8lzUWgQd7P0RJdN
         pH4pod38B5gOKRh+Ht16rsqCu4rfyD1fV9pT6ksdU2S3eWY0fBlwP0kCEScrOvqdZW/U
         ri82NbGCC6CaCXMvPBOPaEfnYiXHxb+jD247kjhJYPmzO5aP1Llo3JqSeW2xN2X39bJj
         gBg5bQKhwzrgmvfy55yxdFiYXfedjjmZtafYXVK6EoskwbVnUB7sTiOWSFeYLqjnBosl
         L9CQC3ZpKidZCm4s6q1cYtPEHX51Rfmiu/r0aSpldAsPWU1dc1+5dZG9bNY2j240uXHc
         wdow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=dQkZNFnV;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id m7si292219lfq.0.2021.09.23.01.15.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 01:15:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A60422027D;
	Thu, 23 Sep 2021 08:15:12 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 13F2613DC7;
	Thu, 23 Sep 2021 08:15:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id ojiaA5A3TGF2FQAAMHmgww
	(envelope-from <jgross@suse.com>); Thu, 23 Sep 2021 08:15:12 +0000
Subject: Re: [PATCH 3/3] memblock: cleanup memblock_free interface
To: Mike Rapoport <rppt@kernel.org>,
 Linus Torvalds <torvalds@linux-foundation.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, devicetree@vger.kernel.org,
 iommu@lists.linux-foundation.org, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, linux-alpha@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-efi@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-mm@kvack.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
 linux-snps-arc@lists.infradead.org, linux-um@lists.infradead.org,
 linux-usb@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
 Mike Rapoport <rppt@linux.ibm.com>
References: <20210923074335.12583-1-rppt@kernel.org>
 <20210923074335.12583-4-rppt@kernel.org>
From: "'Juergen Gross' via kasan-dev" <kasan-dev@googlegroups.com>
Message-ID: <60c0d0f9-e4c6-ef66-b85b-0d091f8cba15@suse.com>
Date: Thu, 23 Sep 2021 10:15:11 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.12.0
MIME-Version: 1.0
In-Reply-To: <20210923074335.12583-4-rppt@kernel.org>
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="zppOVwffTjZ5Oe49Vq0wbEbRvLUF4dOID"
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=dQkZNFnV;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.29 as permitted
 sender) smtp.mailfrom=jgross@suse.com;       dmarc=pass (p=QUARANTINE sp=NONE
 dis=NONE) header.from=suse.com
X-Original-From: Juergen Gross <jgross@suse.com>
Reply-To: Juergen Gross <jgross@suse.com>
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

This is an OpenPGP/MIME signed message (RFC 4880 and 3156)
--zppOVwffTjZ5Oe49Vq0wbEbRvLUF4dOID
Content-Type: multipart/mixed; boundary="AxmgW1XtM0JJFTzWHwG0o4gfWFl7DFvoM";
 protected-headers="v1"
From: Juergen Gross <jgross@suse.com>
To: Mike Rapoport <rppt@kernel.org>,
 Linus Torvalds <torvalds@linux-foundation.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, devicetree@vger.kernel.org,
 iommu@lists.linux-foundation.org, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, linux-alpha@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-efi@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-mm@kvack.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
 linux-snps-arc@lists.infradead.org, linux-um@lists.infradead.org,
 linux-usb@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 sparclinux@vger.kernel.org, xen-devel@lists.xenproject.org,
 Mike Rapoport <rppt@linux.ibm.com>
Message-ID: <60c0d0f9-e4c6-ef66-b85b-0d091f8cba15@suse.com>
Subject: Re: [PATCH 3/3] memblock: cleanup memblock_free interface
References: <20210923074335.12583-1-rppt@kernel.org>
 <20210923074335.12583-4-rppt@kernel.org>
In-Reply-To: <20210923074335.12583-4-rppt@kernel.org>

--AxmgW1XtM0JJFTzWHwG0o4gfWFl7DFvoM
Content-Type: multipart/mixed;
 boundary="------------CFB99E0866EE66F8CFC01FC3"
Content-Language: en-US

This is a multi-part message in MIME format.
--------------CFB99E0866EE66F8CFC01FC3
Content-Type: text/plain; charset="UTF-8"; format=flowed

On 23.09.21 09:43, Mike Rapoport wrote:
> From: Mike Rapoport <rppt@linux.ibm.com>
> 
> For ages memblock_free() interface dealt with physical addresses even
> despite the existence of memblock_alloc_xx() functions that return a
> virtual pointer.
> 
> Introduce memblock_phys_free() for freeing physical ranges and repurpose
> memblock_free() to free virtual pointers to make the following pairing
> abundantly clear:
> 
> 	int memblock_phys_free(phys_addr_t base, phys_addr_t size);
> 	phys_addr_t memblock_phys_alloc(phys_addr_t base, phys_addr_t size);
> 
> 	void *memblock_alloc(phys_addr_t size, phys_addr_t align);
> 	void memblock_free(void *ptr, size_t size);
> 
> Replace intermediate memblock_free_ptr() with memblock_free() and drop
> unnecessary aliases memblock_free_early() and memblock_free_early_nid().
> 
> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>

arch/x86/xen/ parts: Reviewed-by: Juergen Gross <jgross@suse.com>


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/60c0d0f9-e4c6-ef66-b85b-0d091f8cba15%40suse.com.

--------------CFB99E0866EE66F8CFC01FC3
Content-Type: application/pgp-keys;
 name="OpenPGP_0xB0DE9DD628BF132F.asc"
Content-Transfer-Encoding: quoted-printable
Content-Description: OpenPGP public key
Content-Disposition: attachment;
 filename="OpenPGP_0xB0DE9DD628BF132F.asc"

-----BEGIN PGP PUBLIC KEY BLOCK-----

xsBNBFOMcBYBCACgGjqjoGvbEouQZw/ToiBg9W98AlM2QHV+iNHsEs7kxWhKMjrioyspZKOBy=
cWx
w3ie3j9uvg9EOB3aN4xiTv4qbnGiTr3oJhkB1gsb6ToJQZ8uxGq2kaV2KL9650I1SJvedYm8O=
f8Z
d621lSmoKOwlNClALZNew72NjJLEzTalU1OdT7/i1TXkH09XSSI8mEQ/ouNcMvIJNwQpd369y=
9bf
IhWUiVXEK7MlRgUG6MvIj6Y3Am/BBLUVbDa4+gmzDC9ezlZkTZG2t14zWPvxXP3FAp2pkW0xq=
G7/
377qptDmrk42GlSKN4z76ELnLxussxc7I2hx18NUcbP8+uty4bMxABEBAAHNHEp1ZXJnZW4gR=
3Jv
c3MgPGpnQHBmdXBmLm5ldD7CwHkEEwECACMFAlOMcBYCGwMHCwkIBwMCAQYVCAIJCgsEFgIDA=
QIe
AQIXgAAKCRCw3p3WKL8TL0KdB/93FcIZ3GCNwFU0u3EjNbNjmXBKDY4FUGNQH2lvWAUy+dnyT=
hpw
dtF/jQ6j9RwE8VP0+NXcYpGJDWlNb9/JmYqLiX2Q3TyevpB0CA3dbBQp0OW0fgCetToGIQrg0=
MbD
1C/sEOv8Mr4NAfbauXjZlvTj30H2jO0u+6WGM6nHwbh2l5O8ZiHkH32iaSTfN7Eu5RnNVUJbv=
oPH
Z8SlM4KWm8rG+lIkGurqqu5gu8q8ZMKdsdGC4bBxdQKDKHEFExLJK/nRPFmAuGlId1E3fe10v=
5QL
+qHI3EIPtyfE7i9Hz6rVwi7lWKgh7pe0ZvatAudZ+JNIlBKptb64FaiIOAWDCx1SzR9KdWVyZ=
2Vu
IEdyb3NzIDxqZ3Jvc3NAc3VzZS5jb20+wsB5BBMBAgAjBQJTjHCvAhsDBwsJCAcDAgEGFQgCC=
QoL
BBYCAwECHgECF4AACgkQsN6d1ii/Ey/HmQf/RtI7kv5A2PS4RF7HoZhPVPogNVbC4YA6lW7Dr=
Wf0
teC0RR3MzXfy6pJ+7KLgkqMlrAbN/8Dvjoz78X+5vhH/rDLa9BuZQlhFmvcGtCF8eR0T1v0nC=
/nu
AFVGy+67q2DH8As3KPu0344TBDpAvr2uYM4tSqxK4DURx5INz4ZZ0WNFHcqsfvlGJALDeE0Lh=
ITT
d9jLzdDad1pQSToCnLl6SBJZjDOX9QQcyUigZFtCXFst4dlsvddrxyqT1f17+2cFSdu7+ynLm=
XBK
7abQ3rwJY8SbRO2iRulogc5vr/RLMMlscDAiDkaFQWLoqHHOdfO9rURssHNN8WkMnQfvUewRz=
80h
SnVlcmdlbiBHcm9zcyA8amdyb3NzQG5vdmVsbC5jb20+wsB5BBMBAgAjBQJTjHDXAhsDBwsJC=
AcD
AgEGFQgCCQoLBBYCAwECHgECF4AACgkQsN6d1ii/Ey8PUQf/ehmgCI9jB9hlgexLvgOtf7PJn=
FOX
gMLdBQgBlVPO3/D9R8LtF9DBAFPNhlrsfIG/SqICoRCqUcJ96Pn3P7UUinFG/I0ECGF4EvTE1=
jnD
kfJZr6jrbjgyoZHiw/4BNwSTL9rWASyLgqlA8u1mf+c2yUwcGhgkRAd1gOwungxcwzwqgljf0=
N51
N5JfVRHRtyfwq/ge+YEkDGcTU6Y0sPOuj4Dyfm8fJzdfHNQsWq3PnczLVELStJNdapwPOoE+l=
otu
fe3AM2vAEYJ9rTz3Cki4JFUsgLkHFqGZarrPGi1eyQcXeluldO3m91NK/1xMI3/+8jbO0tsn1=
tqS
EUGIJi7ox80eSnVlcmdlbiBHcm9zcyA8amdyb3NzQHN1c2UuZGU+wsB5BBMBAgAjBQJTjHDrA=
hsD
BwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQsN6d1ii/Ey+LhQf9GL45eU5vOowA2u5N3=
g3O
ZUEBmDHVVbqMtzwlmNC4k9Kx39r5s2vcFl4tXqW7g9/ViXYuiDXb0RfUpZiIUW89siKrkzmQ5=
dM7
wRqzgJpJwK8Bn2MIxAKArekWpiCKvBOB/Cc+3EXE78XdlxLyOi/NrmSGRIov0karw2RzMNOu5=
D+j
LRZQd1Sv27AR+IP3I8U4aqnhLpwhK7MEy9oCILlgZ1QZe49kpcumcZKORmzBTNh30FVKK1Evm=
V2x
AKDoaEOgQB4iFQLhJCdP1I5aSgM5IVFdn7v5YgEYuJYx37IoN1EblHI//x/e2AaIHpzK5h88N=
Eaw
QsaNRpNSrcfbFmAg987ATQRTjHAWAQgAyzH6AOODMBjgfWE9VeCgsrwH3exNAU32gLq2xvjpW=
nHI
s98ndPUDpnoxWQugJ6MpMncr0xSwFmHEgnSEjK/PAjppgmyc57BwKII3sV4on+gDVFJR6Y8ZR=
wgn
BC5mVM6JjQ5xDk8WRXljExRfUX9pNhdE5eBOZJrDRoLUmmjDtKzWaDhIg/+1Hzz93X4fCQkNV=
bVF
LELU9bMaLPBG/x5q4iYZ2k2ex6d47YE1ZFdMm6YBYMOljGkZKwYde5ldM9mo45mmwe0icXKLk=
pEd
IXKTZeKDO+Hdv1aqFuAcccTg9RXDQjmwhC3yEmrmcfl0+rPghO0Iv3OOImwTEe4co3c1mwARA=
QAB
wsBfBBgBAgAJBQJTjHAWAhsMAAoJELDendYovxMvQ/gH/1ha96vm4P/L+bQpJwrZ/dneZcmEw=
Tbe
8YFsw2V/Buv6Z4Mysln3nQK5ZadD534CF7TDVft7fC4tU4PONxF5D+/tvgkPfDAfF77zy2AH1=
vJz
Q1fOU8lYFpZXTXIHb+559UqvIB8AdgR3SAJGHHt4RKA0F7f5ipYBBrC6cyXJyyoprT10EMvU8=
VGi
wXvTyJz3fjoYsdFzpWPlJEBRMedCot60g5dmbdrZ5DWClAr0yau47zpWj3enf1tLWaqcsuylW=
svi
uGjKGw7KHQd3bxALOknAp4dN3QwBYCKuZ7AddY9yjynVaD5X7nF9nO5BjR/i1DG86lem3iBDX=
zXs
ZDn8R38=3D
=3D2wuH
-----END PGP PUBLIC KEY BLOCK-----

--------------CFB99E0866EE66F8CFC01FC3--

--AxmgW1XtM0JJFTzWHwG0o4gfWFl7DFvoM--

--zppOVwffTjZ5Oe49Vq0wbEbRvLUF4dOID
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wsB5BAABCAAjFiEEhRJncuj2BJSl0Jf3sN6d1ii/Ey8FAmFMN48FAwAAAAAACgkQsN6d1ii/Ey8D
fwf/WV3EUVWvjXkc64q0a0it6LMGy2AtQrh8KdDecuLV8iH5bKTnqNAZOUoV6sYTeiLsSSnRTLOt
yKKjkWsC9/gUsyuO0B8Zw/VX/zoXJqp7T57FfmW+37qcslFuLzImqvDxdU65n/jEbme+VExmw6UF
yy1ATxxxhQIxeTDXB3SfE0f6rX4Fw1DUqQc25bFNpD1wzdp1xG6qhH31/CWUI/V/frEfuzZrrN5F
Uimkqk3+xjrqqpYh2fb/Pwpd77LFOdIrV4gH0oyl0NA3x3QMNi+67FrbMtuRHZij1jnpwoY1RiUc
uVxzINJ+LJh0g8836hHAkPh5tQNBjV7C6V7LXddn6g==
=Fnkp
-----END PGP SIGNATURE-----

--zppOVwffTjZ5Oe49Vq0wbEbRvLUF4dOID--
