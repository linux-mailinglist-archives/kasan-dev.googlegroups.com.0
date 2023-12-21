Return-Path: <kasan-dev+bncBCR5PSMFZYORBE6WSCWAMGQE2434LYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id B4D9781B57E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 13:09:57 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-20426695791sf892277fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 04:09:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703160596; cv=pass;
        d=google.com; s=arc-20160816;
        b=V7kX0Z/ZZhfU8jSMeS/dYBKTwM8BkXyAElV3r2pGNG0e7xvM3TKDZF9mJSBzEr1bbx
         BuhJC87uTlB+ir8ok2zTckzVZatvLvpJn1gZLhDjBNhVUZBuz1lvX26Ke5+5Kp1bHZ62
         qDl+hYVeukgMn2eu/zwBd8eN2eznV5eQFDk1+XrVpZvsI0vI89H0O/7lCpXJy/76aYcs
         MRuVBwu3moTmFZt3FTnM1CVvSJiFZYoLEKYNDP1rDa7XTkC6FiDQPwBGtp86Nl4L5v/a
         Ng9iPLlSTdH4jyKcjSi7pDA6mLm+uXeTOS8JXvWokH8Slo0pZuWxx+rMI/mW9wOAiQ5J
         TtSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=0B8m12xqT9ZGXHjLieW2zZ/gPbFp8d+qnc4R1K8HPn4=;
        fh=FU6qZcSgmaGHjzPl8lrwS9gBMevBFWKrlHPqEWT0SwM=;
        b=tZI4S71PSLcuQ/cn7yS04t4m0IB+VQDe+W0MoITC59K7ldj6KjTiKqQTE/ijmkiIFQ
         166H4oMH9aP28CpXDGSDpqA/YO6beYb6G5IsSPu88Ol7TUG6x25Or/hzEyPJfgxpTCTl
         nq0AjqSu7xoNp/k6z0gvlqj+rF6Ahd//qoMIj4fbEwIb9vmDrXOvsyqAiQ8YA3e8bpHO
         x8HMEx7DrdO8ONO7SVT9w9geaLVGoH6hPcx1D/KEiaTXKbXR+DYSeFR0+6L7BslJDK9g
         Rh+/FQdYvXz1gCdfGHx6ALLuVl4DBFDCH3tPIzNfMMJp1jT/e+x9WHh3SOBz2rMf4TJ5
         3K5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="UXZ/8iFV";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703160596; x=1703765396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0B8m12xqT9ZGXHjLieW2zZ/gPbFp8d+qnc4R1K8HPn4=;
        b=Njhc+FgJF3F8qB4eFj6EJY5NiL5MQwiQvpDmV1KKlw3sg80g2wD2mOH0p1WucyCqtZ
         FSojruqV3drG8Ar5wzK5NqyUAq9XYWbEOA4irh45wl7CgWzSMXSMhlGH6NUXhxv+LQOx
         hTKsim1BVEhRNuZnEBFzJCSNSAqylxPB/FMLUHgDODmo7ZYMJdrovjwIN8G5wHu970s0
         gm8I+5g2/fJeeDD9HravCaJMdd5YOo6OXzkY02bYIeSmNY8VBDrWcBPf/oVg7SCnpeTh
         +6MS1EzRtlXny2LyS7Yz6RQfleFDX9UNKWix5tQTw/zK+QvrXHLrA9eSv4Zii47N5hy5
         WYZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703160596; x=1703765396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0B8m12xqT9ZGXHjLieW2zZ/gPbFp8d+qnc4R1K8HPn4=;
        b=oW2NPiu88Ix51vZa0K4BVjKyPRALX7U2zjgeEo0eT2JhEtpcWrG3AnUxjmW1Z9qeSV
         f9C90qOSh3XsOGG/KRBFxYalnxnpNz+ZOX4yu82Qtq+TUQQCBqD2nB4jlfkyFHGcwb0h
         W4zvsHQpRYU9Ssbd5euQYdQmXoZlef9Qcfp75Tc6vNGI9d+6deutYG6rX2xGZwdMc8xW
         EyBde0Pbc64QR9F6kGiuTI/szLkfVetjPvpjeJnwT8vIm63m0Mr3xdfHZWq3ED5gvi3Q
         cHxiN4mAX2GFeGpBi6S8mnLCibfkvo1Rr0dI3rieLL79PGkuaqw03euT5RjfH77NZ+9i
         NYQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxdaewet/8jbBNh+WFN+UlrmDb2JCRsD9V8kKwQ7OuA1xAlziYX
	n+qjc5b1ooGQMkv2T1cv6+w=
X-Google-Smtp-Source: AGHT+IHYXkK6Gdqv1dQscaemJ/6jqRTyCkk7L8XKDpnYbUIESwwqArZ/Ggbz0+xOdCWzfszWeG8Npg==
X-Received: by 2002:a05:6870:c10d:b0:1fa:e9f1:ade8 with SMTP id f13-20020a056870c10d00b001fae9f1ade8mr1505697oad.22.1703160596178;
        Thu, 21 Dec 2023 04:09:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1d08:b0:203:d1ed:2a38 with SMTP id
 pa8-20020a0568701d0800b00203d1ed2a38ls210611oab.2.-pod-prod-01-us; Thu, 21
 Dec 2023 04:09:55 -0800 (PST)
X-Received: by 2002:a05:6870:9e94:b0:1fb:75a:6d41 with SMTP id pu20-20020a0568709e9400b001fb075a6d41mr1835114oab.104.1703160595142;
        Thu, 21 Dec 2023 04:09:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703160595; cv=none;
        d=google.com; s=arc-20160816;
        b=J8Gooi94CNRYLmaOWQl4H0UjQYB9g3deijbhDK24ROKWWJazo38m/no8qsrwqIEax9
         E4sMqW+x4YGmpkdGiZ+kR7rZLJNJoCedx63Rebh4sFr7m8KlxN9BnCIDZgNKRj7EgdXn
         NKx9XyQA3rehQ//0YbgVg6HvOWf1eX/By7A3JPxYx2a238x22PgiqGpNkKWRGGUbH65c
         U78AREIed65aF8SJdWSDEo68wrjmvWk3fhUWorpI6AxYf++8n7lBKme81Oos1za3jkVz
         6GVP+XhlLbnJvHXDdm9MpRHpOXIZsARrWoQrMCf18La/RpU7LJWE8evRggffHR1fTCzY
         KJsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=HNgAHhgASKG5cC6HA2RaRQqlTLp7bCesqBG34hJxbJ8=;
        fh=FU6qZcSgmaGHjzPl8lrwS9gBMevBFWKrlHPqEWT0SwM=;
        b=TtsOpXkO97n6yVD7zuc1IZXtOPl1+weepfpxm/bPgWuFOrA2OFrlTam+D4HVtvE66P
         zvh8KobAvuSt6gpac807i2/QUY8n/jMWcd/sK8RMp7y6xCNpdg8kvyGG+T57kLIP6di0
         40Rmu7J72pZDSAdlRmh5KYY+eqLJSkSOiUXdpGS2V9c/LaECuGHOagnyYFnKiOcfnOKB
         KAhHkiwHjlF1EqHhY2fefXoUaAF8fznIhxH2z749EuVdDR4xzjUpPykVbSuSZb4Xv5UX
         Iq9O38tK4+g9acaoA7CeBA+sUlMQGaJ7QnHkTECEQ+EuStcKBGa0BVLT6OQkNp/Wuelq
         ttqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="UXZ/8iFV";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id t5-20020a05680800c500b003aef18f3442si156348oic.0.2023.12.21.04.09.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 04:09:54 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4Swq4G3W56z4xCg;
	Thu, 21 Dec 2023 23:09:50 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, Nicholas Miehlbradt
 <nicholas@linux.ibm.com>, "glider@google.com" <glider@google.com>,
 "elver@google.com" <elver@google.com>, "dvyukov@google.com"
 <dvyukov@google.com>, "akpm@linux-foundation.org"
 <akpm@linux-foundation.org>, "npiggin@gmail.com" <npiggin@gmail.com>
Cc: "linux-mm@kvack.org" <linux-mm@kvack.org>, "kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>, "iii@linux.ibm.com" <iii@linux.ibm.com>,
 "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 02/13] hvc: Fix use of uninitialized array in udbg_hvc_putc
In-Reply-To: <aab89390-264f-49bd-8e6e-b69de7f8c526@csgroup.eu>
References: <20231214055539.9420-1-nicholas@linux.ibm.com>
 <20231214055539.9420-3-nicholas@linux.ibm.com>
 <aab89390-264f-49bd-8e6e-b69de7f8c526@csgroup.eu>
Date: Thu, 21 Dec 2023 23:09:49 +1100
Message-ID: <87frzvlpte.fsf@mail.lhotse>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b="UXZ/8iFV";       spf=pass
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
> Le 14/12/2023 =C3=A0 06:55, Nicholas Miehlbradt a =C3=A9crit=C2=A0:
>> All elements of bounce_buffer are eventually read and passed to the
>> hypervisor so it should probably be fully initialized.
>
> should or shall ?
>
>>=20
>> Signed-off-by: Nicholas Miehlbradt <nicholas@linux.ibm.com>
>
> Should be a Fixed: tag ?
>
>> ---
>>   drivers/tty/hvc/hvc_vio.c | 2 +-
>>   1 file changed, 1 insertion(+), 1 deletion(-)
>>=20
>> diff --git a/drivers/tty/hvc/hvc_vio.c b/drivers/tty/hvc/hvc_vio.c
>> index 736b230f5ec0..1e88bfcdde20 100644
>> --- a/drivers/tty/hvc/hvc_vio.c
>> +++ b/drivers/tty/hvc/hvc_vio.c
>> @@ -227,7 +227,7 @@ static const struct hv_ops hvterm_hvsi_ops =3D {
>>   static void udbg_hvc_putc(char c)
>>   {
>>   	int count =3D -1;
>> -	unsigned char bounce_buffer[16];
>> +	unsigned char bounce_buffer[16] =3D { 0 };
>
> Why 16 while we have a count of 1 in the call to hvterm_raw_put_chars() ?

Because hvterm_raw_put_chars() calls hvc_put_chars() which requires a 16
byte buffer, because it passes the buffer directly to firmware which
expects a 16 byte buffer.

It's a pretty horrible calling convention, but I guess it's to avoid
needing another bounce buffer inside hvc_put_chars().

We should probably do the change below, to at least document the
interface better.

cheers


diff --git a/arch/powerpc/include/asm/hvconsole.h b/arch/powerpc/include/as=
m/hvconsole.h
index ccb2034506f0..0ee7ed019e23 100644
--- a/arch/powerpc/include/asm/hvconsole.h
+++ b/arch/powerpc/include/asm/hvconsole.h
@@ -22,7 +22,7 @@
  * parm is included to conform to put_chars() function pointer template
  */
 extern int hvc_get_chars(uint32_t vtermno, char *buf, int count);
-extern int hvc_put_chars(uint32_t vtermno, const char *buf, int count);
+extern int hvc_put_chars(uint32_t vtermno, const char buf[16], int count);

 /* Provided by HVC VIO */
 void hvc_vio_init_early(void);
diff --git a/arch/powerpc/platforms/pseries/hvconsole.c b/arch/powerpc/plat=
forms/pseries/hvconsole.c
index 1ac52963e08b..c40a82e49d59 100644
--- a/arch/powerpc/platforms/pseries/hvconsole.c
+++ b/arch/powerpc/platforms/pseries/hvconsole.c
@@ -52,7 +52,7 @@ EXPORT_SYMBOL(hvc_get_chars);
  *     firmware. Must be at least 16 bytes, even if count is less than 16.
  * @count: Send this number of characters.
  */
-int hvc_put_chars(uint32_t vtermno, const char *buf, int count)
+int hvc_put_chars(uint32_t vtermno, const char buf[16], int count)
 {
        unsigned long *lbuf =3D (unsigned long *) buf;
        long ret;
diff --git a/drivers/tty/hvc/hvc_vio.c b/drivers/tty/hvc/hvc_vio.c
index 736b230f5ec0..011b239a7e52 100644
--- a/drivers/tty/hvc/hvc_vio.c
+++ b/drivers/tty/hvc/hvc_vio.c
@@ -115,7 +115,7 @@ static int hvterm_raw_get_chars(uint32_t vtermno, char =
*buf, int count)
  *       you are sending fewer chars.
  * @count: number of chars to send.
  */
-static int hvterm_raw_put_chars(uint32_t vtermno, const char *buf, int cou=
nt)
+static int hvterm_raw_put_chars(uint32_t vtermno, const char buf[16], int =
count)
 {
        struct hvterm_priv *pv =3D hvterm_privs[vtermno];

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87frzvlpte.fsf%40mail.lhotse.
