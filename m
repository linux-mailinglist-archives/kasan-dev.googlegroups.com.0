Return-Path: <kasan-dev+bncBCKLNNXAXYFBBJWFWK4QMGQE33KTMHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7668D9C03C4
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 12:21:12 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-37d609ef9f7sf486114f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 03:21:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730978472; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wy5MUu85CsPCKG8or9HPqihmRQP4hBdOgnb7P0R1USjn4Vw/HJtWfv9W8d181CYWba
         RWss4ZLPP7NBb4bj3ToOyuFtho4Kk2h6TQxXQ9NXC3Av2+D9LyCDO5JlpwmSvlzRHtHC
         lQHEY4DI29wBXBpOIYvnVt1HO7pS0hZ3jN+V5B6Y/cjbuXwpIL1mfwkaOfVm1l9SrPIK
         lnM7p+jrzphU9ysZJhzRrfX7pStv61aALUXeg7RNCMSIpuZVYv5CoYy6UKBD2YmpUqog
         +9SyffVWIqDl5U/6ejoqGWizLitvNJUjoLzRFW27wHxTpulVcDN2JshSuAioenjcFlRm
         qyxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=xMrNjw+gtIUfwqkEyoO/PGmSs+7MjxS2B7yRsAwWaLo=;
        fh=D72/RgGWLhyur/Wkyhx88bOhKNe6FwuW3kPoI8Ptmf0=;
        b=SfBz+30aSB2OAVdNANenvyNkHiUfri4lw5J5Z424haODhx1dl6wh3RV0WAcmlCvWNB
         sJBIgGBJMeNVSzVNA+qRlhmTInQNYtII88cWjRzgLPOyB7Sen0WhBz3GY05PoUdk1dM9
         Zfg6kHMVrwzroKWdjMjSD4iSHYmN6TzPHnpUZnoA6gM8gNwpiLELdXwCDujq9xR6BpXL
         3Sv0D+YxvLwFMf/pr5OFE+CqjZJet2ISZUmls9Ww51rNXsXGynuyiIhPIUJsh3rhecZT
         RCnSiLbMexagz67Erq12omdECy4gSJ2/mzp5iegWvuMHMzsQONMgqGc7KdXi9RZvdX7W
         vtmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=W3C6oGXE;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730978472; x=1731583272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xMrNjw+gtIUfwqkEyoO/PGmSs+7MjxS2B7yRsAwWaLo=;
        b=Ulvl/6PJmb4fcDLhty23fVPCerYBhyNVGwZBpPOcnRL4FKjLpCF3O7b56Z+wjAG77r
         DwnP4TP0WS0bJZWMH3UpHtUn13ePYwb8X3JpWDtBLECxQ116hRcQiivy6GVEqRV6HUJp
         +GXm8DXRLbQDaKrIiODUBIGJrpZZ6anbvXPRMSCnM9OBN5WeuNzqY9/carh/o0Ck8kZs
         vJSMTJ/ZzVANHhIWFsQokDQGXpJxIZ+44LbLtdvA0M11yEUm/ia7F2QPlcfwBpsQm9In
         KBSfgVDq2xSiWz1T7LU/Hh02WRz/M9k50m98gM8tjW0k2/U+VuwFH60CrWSMt7tVdu2+
         jJJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730978472; x=1731583272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xMrNjw+gtIUfwqkEyoO/PGmSs+7MjxS2B7yRsAwWaLo=;
        b=AfPXF4wvuD20CaNAiS6eJCYh1mbtB07uUTTLlKdC7k/03nOrvpyOi5A0I3xXobIomR
         4LldwPq7o1WzTLoGICtu5+Prgc5bcBxQVRMF06Y7dMjvCn85MHEVvx1qvd40oO4l6xR4
         L3jlA4HK4fpIgHI/kK6E8Vzly8+DY+XUfi+Co9Wdm+PaKrkM+dahw5m15nQsI5nj8VFf
         mTgy7wr+4sikblJPr55QUl53TdIi33EcBqjkauj97bAy5XnScx1A8HHn8LCW+bvdXPso
         uEOGcm5I2dF7QpsgquRwjwKMNnChPb1tmGbkBwjUCW2Nmhs9ku3j5D2TW/9AbR+gFQM3
         ocXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPbRqWw3UZC5hrdoVGvYoImeIpYtF+CiRG5Bbxl6TRZGuX2hAFHJkUIXVWJVB+wuiivhnvMA==@lfdr.de
X-Gm-Message-State: AOJu0YwHY3YZs/vgUUmUGB+JxrNL8EcTi6K6/rk9w3u6YHwnYYHN33Pm
	VVpxMh1oYgpaTooq48JyCAkjQa/2vFEnezlTpQ6IuLTKHeVRwQo5
X-Google-Smtp-Source: AGHT+IGaz+d9VGqyGyoryTBSYyZO6R2gYkabhcBv0991CsBQFqKscwSA54XSIM/wfLE/6V+oDfF5Pw==
X-Received: by 2002:a05:6000:1548:b0:37d:4cd5:fff2 with SMTP id ffacd0b85a97d-381ef681c7emr752508f8f.6.1730978471297;
        Thu, 07 Nov 2024 03:21:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fa4b:0:b0:374:c0b6:44bf with SMTP id ffacd0b85a97d-381ec304ae0ls342491f8f.0.-pod-prod-03-eu;
 Thu, 07 Nov 2024 03:21:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXURJEDoKfTXInLWUV6i2oWIA7AVBgQmGB0gxQGE8UOCp6rah5pjN2EijicrxQh+9kY9iyYEuAwqgg=@googlegroups.com
X-Received: by 2002:a05:6000:184d:b0:37d:4870:dedf with SMTP id ffacd0b85a97d-381ef6a1c1cmr617970f8f.19.1730978468812;
        Thu, 07 Nov 2024 03:21:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730978468; cv=none;
        d=google.com; s=arc-20240605;
        b=i0idyG9jgQmsALGWTMXo2EPvPkU4q1eQwCU7ma3Pje1g/4fqPDqcfIYtufehBT/+kL
         Qk6zI4Bca4OTsx9pnVV5LDzmVhO9mNPPY8YvLMDTQzwumBxS/FolkXmMruWinnIU2LPe
         3VSuN3QHQqy44D9Zu+sWqriT97vdPaCcA6GgXXsu+HZixP4mTJxqilgfld3f+MtAnAPd
         GwGfsJHu/DcwHUeOL+yQpt18eypxqcgA4/1S02OMZRD8tSmmvKT0DKyMHA5vVqx13B4Q
         Xr0tAzKOO4OQ3AILrB1SnItXAVAhddEhVmYqkNboLLQZLx+7mKKuPSiFHJbAQ/9NdtWo
         HO0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=Tel7mhMevWRKEW+kc/Ko2O9+6EggljMRxxOElNb7ssE=;
        fh=VfHGvZqxKQqO4UHDAf///3jogRXhdEm9pXrv6zZe6tY=;
        b=dTZhzGVLeZkX1LinETLTrhH0Yor8ZKBipvIjWKIyaDKM1DgZ+eQTFRM+wfkTIeyHn3
         6hesEq6akF4ZBbEXR3OdWqma8C7dGV3wKW2e5IVyVt207j3ERK48XOblVwOov3083ype
         MzuUzAellSFVDt8iISJEY3889ydl4vBoDMgGd50lo0iOxkoP/LM7ygyEeifjaA7uhO7j
         4oedQ2EB2N9GTsny60P0nqNCD4ZDezDlnNAYuDkJf9hUAQ6MwKzQ4P5ZlIq6bViEChcc
         P4AOS5+sRMvJUy/FHvEEURfAsHn/mIEp3B7WRcwwdac0GnhkMtWWTXvj/ZupCae0Lzqm
         O7SQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=W3C6oGXE;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-381eda2b03csi45368f8f.7.2024.11.07.03.21.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 03:21:08 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Thu, 7 Nov 2024 12:21:07 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>, Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, sfr@canb.auug.org.au, longman@redhat.com,
	cl@linux.com, penberg@kernel.org, rientjes@google.com,
	iamjoonsoo.kim@lge.com, akpm@linux-foundation.org,
	Tomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH 2/2] scftorture: Use a lock-less list to free memory.
Message-ID: <20241107112107.3rO2RTzX@linutronix.de>
References: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
 <20241104105053.2182833-1-bigeasy@linutronix.de>
 <20241104105053.2182833-2-bigeasy@linutronix.de>
 <ZyluI0A-LSvvbBb9@boqun-archlinux>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <ZyluI0A-LSvvbBb9@boqun-archlinux>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=W3C6oGXE;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2024-11-04 17:00:19 [-0800], Boqun Feng wrote:
> Hi Sebastian,
Hi Boqun,

=E2=80=A6
> I think this needs to be:
>=20
> 		scf_cleanup_free_list(cpu);
>=20
> or
>=20
> 		scf_cleanup_free_list(curcpu);
>=20
> because scfp->cpu is actually the thread number, and I got a NULL
> dereference:
>=20
> [   14.219225] BUG: unable to handle page fault for address: ffffffffb2ff=
7210

Right. Replaced with cpu.
=E2=80=A6
>=20
> Another thing is, how do we guarantee that we don't exit the loop
> eariler (i.e. while there are still callbacks on the list)? After the
> following scftorture_invoke_one(), there could an IPI pending somewhere,
> and we may exit this loop if torture_must_stop() is true. And that IPI
> might add its scf_check to the list but no scf_cleanup_free_list() is
> going to handle that, right?

Okay. Assuming that IPIs are done by the time scf_torture_cleanup is
invoked, I added scf_cleanup_free_list() for all CPUs there.

Reposted at
	https://lore.kernel.org/20241107111821.3417762-1-bigeasy@linutronix.de

> Regards,
> Boqun

Sebastian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0241107112107.3rO2RTzX%40linutronix.de.
