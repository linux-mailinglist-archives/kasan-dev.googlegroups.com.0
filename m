Return-Path: <kasan-dev+bncBCR5PSMFZYORBVEEQCNAMGQEBMU3JAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A81B15F7700
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 12:41:26 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id o14-20020a056a00214e00b0056238ef46ebsf2672975pfk.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 03:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665139285; cv=pass;
        d=google.com; s=arc-20160816;
        b=anKbsFTVY0HkWPD4XN1QMaGmsRSqaMq8xO5DTDW6UIqWMngN07moJKT0tWud5zyfOV
         JkVBCDzJaDauEhQbebQt7vl9LVdlHZHj9EH2t5EhkIBG8GEgGtG0RSSp8BiXNteP4jAA
         ywK/ftcJAE/eKPolvQ5g9TddHtozlVZ476JoZB5EuQs7OwYPfLk9bDapMxQp/BrxfkWs
         4EQIE48j3SlKO4rUA49jf3vIsCZ2egREO5hG2H8fVGfPhC8ltX1EuGpey96ubdvK55D1
         HID34Qq/VPpaamyTJq/QjmjiyYD9XTGtvN1pzRx38KgNE3r1w/M+2tqlc3I5SW2N+fLV
         8WIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:to:from
         :sender:dkim-signature;
        bh=x0TWqL7PcOPMgCDudNkBWeK6WLoCsTn0F1qeLIG3wX0=;
        b=CDLx+BP1ls6KE29RHkY2l+R1HrJCc6J4bDNpFdZPWIlMDVmvKloAqyfowFzc3RvaVX
         IwymgdBAiqXJ1J5Rau7OJ7de52b3WQ1LsSYoTIqnxcGGXvR2BgDUCk1bl3ix/TGfgAGG
         o1plfdcinA0WJgxo3VmpozEj7y0II/JzTHqJpbM3pT3L9x5jCYw3rdq2FnJW/KO8HhZf
         k+kQ71Vv71xxg7GYwK4VP+G7ZJGI+CIwJ/lWmDSY9c9Fn832ig7ni1vfm9mrXUZ/qx+Y
         qsFgLnNtBG2t6YrFBno1YoMNvj1rONrTpwx8lsiWTpsPBNXqOD8axMTNMTPA+QV0msW4
         uAFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=aipWrbBL;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x0TWqL7PcOPMgCDudNkBWeK6WLoCsTn0F1qeLIG3wX0=;
        b=fUkJaqMujPgUPSoYtGbLEhWVcHlnA6vjCvalSuAHdFEHTnuIUrdPAQcQBGTB6paDXA
         iZqBAR7ud6BEY8c2MezUMk8RlOO0/TCSHVciQhlvCQmFSox/C4LUfgDManRDHMMmZBZF
         WD1C3269qCe1YuDVu/XZRqBGbp66IsD4to3FaQ1ddy0GVZ2JZqbSCFxM/9Smreip9J/6
         FvKqTy2B4BPtl8M0O9SrvCxt0LhbH6wAnpT2APO85meyqIXq8qil2kR8Dbvkfq6AuNMm
         sRrZavgKvPZs0e3tLbhN+YvBhPRISc2jIpfUWJoGSPFCShq0EiUU0a771jT2CV7MQyO8
         GihQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:to:from:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x0TWqL7PcOPMgCDudNkBWeK6WLoCsTn0F1qeLIG3wX0=;
        b=HGJ72FQl4XnNxAvnI4mRdFkQog/9e2Z18jxT3bHekX6bPMU+7UxVyMZNTYXu0QoJYX
         57MRctMMcqQD6j9EF0i7ksVcqDuTQ9gtS/lIuInyTPyFA/ZcPmK9m3Xzzk7VLDKICIPb
         DduDxLi8+Udm2KFzdjCfZ/nACuaqXKqHy0oHd2mjso0mTEpsvzXgUH3FKifTzxWH3R1A
         pdxkkDovtNnkQd11S19dKws/PsAGK/aSViCqnAYtJ8Nh1W7hT47sNw192NY0kBM0cSfp
         WiFaoRseL5twZF2EXA3cSMk7EM1s5pUmhK6oYbvPZJCJ9SoZKfbCaPOnJ2TzZzvQwBhG
         GoKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3Qa1EyTObFd9dKu1jsE6hDsFj4kIqArNoAEQ1meepBgG0b0Cxz
	o00gne2vpQN2Iy1r3Zcb34k=
X-Google-Smtp-Source: AMsMyM7mX0/v0nFthSGIJb3pNEgxLoQGWc8A9l8Q/oI7KnXRGOhqg6lSJfzpmTV2TI80INhXS2JiOA==
X-Received: by 2002:a65:6055:0:b0:42a:7b2b:dc71 with SMTP id a21-20020a656055000000b0042a7b2bdc71mr3916355pgp.23.1665139284928;
        Fri, 07 Oct 2022 03:41:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:91c9:0:b0:43c:e346:6c2f with SMTP id l192-20020a6391c9000000b0043ce3466c2fls2515976pge.3.-pod-prod-gmail;
 Fri, 07 Oct 2022 03:41:24 -0700 (PDT)
X-Received: by 2002:a62:e519:0:b0:561:e56e:1e92 with SMTP id n25-20020a62e519000000b00561e56e1e92mr4618852pff.66.1665139284227;
        Fri, 07 Oct 2022 03:41:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665139284; cv=none;
        d=google.com; s=arc-20160816;
        b=wB9XIOjdlOBn3kkdC8ppgQpdmqk5mYhqIJ+0vQ1VhyQH819IwrTLDqY5dhwZADXfwP
         4dYVMYRQvZgri2ruMeBJ32Uztn3JPNf2+p+Yob0mMF8iOqEBKAIlq1RTeNY4KKxQ02Lj
         WFWHMbdn1D+PWdA2SNumS8TkwlEMzIzFDIoLARCQaLvaAXNz6HGQFXVCc9IIMD+oV1jL
         yRSGA/k7hOZplwKxmXn22GCAJaBY7OqJC6RWhQONtj69t6D8zQXe17ynLcbAgKyUt7Wo
         bcUxkrFmqz/ge8gepDF/pHP6oB8CkvHhLLT6y94ZkbO85T7ZcaPRgCh+hsyGnAzINse0
         MSCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:to:from:dkim-signature;
        bh=UR2MeUI/j4OkA0mD873etMijpD0UYiYWP9Zb1OCdxjg=;
        b=VDZFQSrdePtwfciwLQVUwTT3y0kub66JchbrPYKD9ThxF+9dsuYYMvVglBGt1XNbAp
         rMKlY32ns2x888NpTKWB3xRQp87rE9XpgeasaRRWw3mTaQPXvnd/D5oQLRjerO/6CoKx
         qtap/+jyp7FAmMgXaTy6QxLux7MFfjHq8Iu2BPqzqeW7306rh0Tz4jkUIj+XgQcJISb5
         FATTPb8RUv54305j8e75k/xpPPfvKDwWF1LeqzeJM6kmjTGfxIkcEX+aK1oxWH0vcV+P
         ey9KrYkfxtVNT0TNgBa6OWpRgMmFDdiSQci3qMZLFioKhz8ziKWGZHRvzIvx1y8gPlNI
         XwYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=aipWrbBL;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id mt16-20020a17090b231000b0020ad68cb48fsi304484pjb.0.2022.10.07.03.41.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Oct 2022 03:41:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4MkPxF3b4nz4xFv;
	Fri,  7 Oct 2022 21:41:21 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, Nathan Lynch
 <nathanl@linux.ibm.com>, "linuxppc-dev@lists.ozlabs.org"
 <linuxppc-dev@lists.ozlabs.org>, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
In-Reply-To: <9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38@csgroup.eu>
References: <20221004223724.38707-1-nathanl@linux.ibm.com>
 <874jwhpp6g.fsf@mpe.ellerman.id.au>
 <9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38@csgroup.eu>
Date: Fri, 07 Oct 2022 21:41:18 +1100
Message-ID: <87h70for01.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=aipWrbBL;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:
> + KASAN list
>
> Le 06/10/2022 =C3=A0 06:10, Michael Ellerman a =C3=A9crit=C2=A0:
>> Nathan Lynch <nathanl@linux.ibm.com> writes:
>>> kasan is known to crash at boot on book3s_64 with non-radix MMU. As
>>> noted in commit 41b7a347bf14 ("powerpc: Book3S 64-bit outline-only
>>> KASAN support"):
>>>
>>>    A kernel with CONFIG_KASAN=3Dy will crash during boot on a machine
>>>    using HPT translation because not all the entry points to the
>>>    generic KASAN code are protected with a call to kasan_arch_is_ready(=
).
>>=20
>> I guess I thought there was some plan to fix that.
>
> I was thinking the same.
>
> Do we have a list of the said entry points to the generic code that are=
=20
> lacking a call to kasan_arch_is_ready() ?
>
> Typically, the BUG dump below shows that kasan_byte_accessible() is=20
> lacking the check. It should be straight forward to add=20
> kasan_arch_is_ready() check to kasan_byte_accessible(), shouldn't it ?

Yes :)

And one other spot, but the patch below boots OK for me. I'll leave it
running for a while just in case there's a path I've missed.

cheers


diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 69f583855c8b..5def0118f2cd 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -377,6 +377,9 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *=
object,
=20
 static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 {
+	if (!kasan_arch_is_ready())
+		return false;
+
 	if (ptr !=3D page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 437fcc7e77cf..017d3c69e3b3 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -191,7 +191,12 @@ bool kasan_check_range(unsigned long addr, size_t size=
, bool write,
=20
 bool kasan_byte_accessible(const void *addr)
 {
-	s8 shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
+	s8 shadow_byte;
+
+	if (!kasan_arch_is_ready())
+		return true;
+
+	shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
=20
 	return shadow_byte >=3D 0 && shadow_byte < KASAN_GRANULE_SIZE;
 }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87h70for01.fsf%40mpe.ellerman.id.au.
