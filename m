Return-Path: <kasan-dev+bncBDB3VRMVXIPRBXHMWCFAMGQEZSDKMAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 734044159C5
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 10:10:05 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id i40-20020a0565123e2800b003f53da59009sf5385649lfv.16
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 01:10:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632384605; cv=pass;
        d=google.com; s=arc-20160816;
        b=MsyZibI5MR+by+XFpr30hJ99K64ZCHikRKVnnHJrafto6H8zf0oSKGoKh+lm7ObbWS
         i3wadbD7b9rtZpKZUXQDrhDdfSnCA+qATyWz6bE6JPrxOIkVXjz6JvtTR26CGyQuv34A
         EEzPywua4/EX9fpSKku61f04NtBgyOlrYYE6RCyNjF3VSXVGWF4i69Aj42Nlrcn5O66q
         optIlRksoe9468EvfmRctbsdvviega6bQzP+lzu0RNp1pgt7OviHy+EjuVplfOz9xIZl
         qRXalrHzRwPA4wxZPJv6vjiv5sGyuNjr/GwTn8lZl/FBGIeKM3Gg6/TLwrpjyIkWGjJl
         OB8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=8ZQcVRd8RrB+/eOjgwX6B4+FhvKnC3BNZEccEAqAXRA=;
        b=by1smcPZXBoI62efX8GEy59oFa+MSlG9jdemJSUU+1FuVxqML746nKMFpSLsOCsF6V
         XIKH1foIt3Q1Z3c+xz1So4xHMZnI2VgnHWuN2BSNehgQtGSgWRHF1InlvhoAVrdgGdmf
         48Hf2VTFcrWkuuY07y5rKJa6n3AOoTAOwA9EyojEg4Gx9ouIV8BEcBXZjxVCpCPe8wCw
         /TSyWLBTIqQ8jv5z/ak2zL4bZ3ZRdtNyBCrt8X0U2Ljj4X3JT0d1pEGeNGN36rmUw4yx
         WdvZpqce5XB/5/FwXXD1WNNv4IVbVkglXsfdoEKKy0Sqlrp/VJ99DKkiAmTlG/ZV2dLB
         vIFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=Zo9jK3BE;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8ZQcVRd8RrB+/eOjgwX6B4+FhvKnC3BNZEccEAqAXRA=;
        b=LKbHSR4eJ+0lQCobY4ix0S0EAidYQY8hgrnPp4Sug2chjhaZwaLxr4aJ1zNknhlUJU
         6VOW/j3m6FlIlCLlt8pw7AbEcvWHMhJLjW8CLtmPv9QpkWuQiNgnWhGVSZ4/dzMrwxM0
         MOxJc60TpA4E4Blqu3UxiVXJW13+mC6jIrQgp5vxxFDqU7iWGWZ/OpQR8spqRlSnaig5
         /RWnb1s4HqeMa/B1IIOf9j8E+CS1O4jM0+57dFo/J9epsdK6ET93m8zLsIz0XSLqbfdW
         d/Oa8zJT6ymZk+W6d0+076fPblYZV2m6uQOsN+ALfl+F0q7QjSY3OHcOUfQaoz/IALMM
         nMAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:subject:to:cc:references:from:message-id:date
         :user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8ZQcVRd8RrB+/eOjgwX6B4+FhvKnC3BNZEccEAqAXRA=;
        b=bLPp7YzACwlyG2BpYsQeafGqEqCKurAfoT7jBQB9DPE6b8nWHa1df6acQaJukLePxP
         74gB1TzPGRrcRHEIgknUkowmr+zkC5A/MybENR8p3yJsaH/9KpiENsSYo6ZeyXicMkxS
         le87TShwXS4SEPu8wqFCYCQWiQOPb3AGS+W+8Hswx95K3WAfi+JMZnEeYxsfBskWJagI
         v2CrsxOIFHsSshpXU9/QuHLgM+xwJc9Kg8AQGVv7WE1sllrrQOwhWdzg+LSTt5rsBx4O
         8EjrhVBYrtnQtPVE75eV7do+KFxKnIkhG3EWJInuYiQD0kEaVdtyHOVBk+66ACBouNHK
         tx/Q==
X-Gm-Message-State: AOAM531WFedebvHaAt6LC5OZJQ1588WwnMtIPrlTdQjjXCBbVgIfcCmm
	nT299EiOVTMPD4Q2Hr6xPIA=
X-Google-Smtp-Source: ABdhPJwm1zKfGkAPxiqvOw7EIO19iA9NHm1WOiDEW1mS307PEGe2/+m8fesbCT5+Lxn7utnsL7mdtA==
X-Received: by 2002:a05:6512:6d4:: with SMTP id u20mr2957233lff.329.1632384604984;
        Thu, 23 Sep 2021 01:10:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f14:: with SMTP id y20ls2139353lfa.1.gmail; Thu,
 23 Sep 2021 01:10:04 -0700 (PDT)
X-Received: by 2002:a19:f515:: with SMTP id j21mr2939939lfb.125.1632384603944;
        Thu, 23 Sep 2021 01:10:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632384603; cv=none;
        d=google.com; s=arc-20160816;
        b=QROnkSZZcBI/EyXiH7EuU5/iPu+T6xbwaiaDZz9QtpL6hCzCEwTMlOPGAPmpVQtANs
         CZB4qwMgKAR9bCJ34V8TtB2jICxeH1YTlIpE9wIZ+aF2WcdimLUtMvjIdOLfmWGBuHBb
         nERMTtJ3z2ig0wjrvo7IsMrf3K6eW4oJhsxs9oLqJxCDHCza05AiY4J5chbA+UHOQ0Aj
         4OwYkX9SMKsyXgsnPjcsfQDx2HL7cieHBe5oe2qEfiyhSznNTmX6yjeEbx8j0VeaEW2M
         +n59xsi2zg8XweDU5XK/OIQDhER5lLF2FicgBsEcsbgeUxCHFsh6DoBbjU2mmtx8LL1/
         bo5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:dkim-signature;
        bh=yCmYQKyQ1CegwpuFA1biRZgl2wD61Tp1f0chBfFWd8E=;
        b=KSVxrm35SoShj1W+Y9tCj6ZuwTxVjuPT9A0aRnStIC/fNQKb1ejfcVHoQUbq4KLkrY
         IlX9l/A0mw45RPxm3oUr1UzjWgmIOUi3hWMOGviYRnxZhNGepMAuM/YdQqTmEW4Evzlf
         xKlnEtngwrWFESEzLmk7ggYWACDAU0MTsI/Jv2rpXAgwX6FCnZcwi+u1X5HuvzV5DIvP
         rivT7Rtu8d/8H/gFIztj+Va3PiCUsD6UneRgSY9JG2zGMAJOJXh51c8WZ+7GOf4dz7iT
         zcqwm+DpIhCHynX+lTvqse+orvp4ECYTkaqgvpZ46Oqh51VtBORfcRNtFeY+L28ZCJbh
         gw1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=Zo9jK3BE;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id a3si338004lji.6.2021.09.23.01.10.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 01:10:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1ED1B221D4;
	Thu, 23 Sep 2021 08:10:03 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 82C6313DC7;
	Thu, 23 Sep 2021 08:10:02 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id hYWfHlo2TGGbEgAAMHmgww
	(envelope-from <jgross@suse.com>); Thu, 23 Sep 2021 08:10:02 +0000
Subject: Re: [PATCH 2/3] xen/x86: free_p2m_page: use memblock_free_ptr() to
 free a virtual pointer
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
 <20210923074335.12583-3-rppt@kernel.org>
From: "'Juergen Gross' via kasan-dev" <kasan-dev@googlegroups.com>
Message-ID: <69c60441-d6d0-96e2-a04e-5bdf87241b4b@suse.com>
Date: Thu, 23 Sep 2021 10:10:01 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.12.0
MIME-Version: 1.0
In-Reply-To: <20210923074335.12583-3-rppt@kernel.org>
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="Ou4UW1xPRLuVMrznu7nRrBvD9qxXwPwpI"
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=Zo9jK3BE;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.28 as permitted
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
--Ou4UW1xPRLuVMrznu7nRrBvD9qxXwPwpI
Content-Type: multipart/mixed; boundary="Opwz8FSwCRvDNIt0szi2Ea4VaFO0qhLYD";
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
Message-ID: <69c60441-d6d0-96e2-a04e-5bdf87241b4b@suse.com>
Subject: Re: [PATCH 2/3] xen/x86: free_p2m_page: use memblock_free_ptr() to
 free a virtual pointer
References: <20210923074335.12583-1-rppt@kernel.org>
 <20210923074335.12583-3-rppt@kernel.org>
In-Reply-To: <20210923074335.12583-3-rppt@kernel.org>

--Opwz8FSwCRvDNIt0szi2Ea4VaFO0qhLYD
Content-Type: multipart/mixed;
 boundary="------------7FABCF9287BBEACE094F562B"
Content-Language: en-US

This is a multi-part message in MIME format.
--------------7FABCF9287BBEACE094F562B
Content-Type: text/plain; charset="UTF-8"; format=flowed

On 23.09.21 09:43, Mike Rapoport wrote:
> From: Mike Rapoport <rppt@linux.ibm.com>
> 
> free_p2m_page() wrongly passes a virtual pointer to memblock_free() that
> treats it as a physical address.
> 
> Call memblock_free_ptr() instead that gets a virtual address to free the
> memory.
> 
> Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>

Reviewed-by: Juergen Gross <jgross@suse.com>


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/69c60441-d6d0-96e2-a04e-5bdf87241b4b%40suse.com.

--------------7FABCF9287BBEACE094F562B
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

--------------7FABCF9287BBEACE094F562B--

--Opwz8FSwCRvDNIt0szi2Ea4VaFO0qhLYD--

--Ou4UW1xPRLuVMrznu7nRrBvD9qxXwPwpI
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wsB5BAABCAAjFiEEhRJncuj2BJSl0Jf3sN6d1ii/Ey8FAmFMNlkFAwAAAAAACgkQsN6d1ii/Ey/u
jwf/Wc7bKSwtYpm6kgk3TsHmpeJbPgh0Zpv1wT9MtIr5veUKbFZsg/Ji0X/gETRJ/GzFem6QpjrD
qfZjjrHW84FjHmrikrdzulZV8SZVqYLSdZWQRL4dja5oWLHT7nPkOtdmNelKufQ3CxAmy1JmVzVb
Mx6gmnvelfR4gvjcbXXvmtdNZvJIKIQ3zLsqDK8z5H0AA3wt7EG/6FFaIZD/lYSqQAmpBXhbvdZe
EmLrt4FExY741RXXb6HIT7WjiQ+iFHRiGgNjAF7OZlY2xzR14fRVqNF56oq8GYvMSJU1knueE60N
Y+1NbMVNCzWoYzBjFB95UGbdvzgBy6XOzZ21ar2IPQ==
=DYUR
-----END PGP SIGNATURE-----

--Ou4UW1xPRLuVMrznu7nRrBvD9qxXwPwpI--
