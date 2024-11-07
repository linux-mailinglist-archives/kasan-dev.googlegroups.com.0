Return-Path: <kasan-dev+bncBCKLNNXAXYFBB3FYWO4QMGQEQZWSTZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CA519C0A14
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 16:27:41 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-431604a3b47sf6821415e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 07:27:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730993261; cv=pass;
        d=google.com; s=arc-20240605;
        b=TJnlLzDZyU146nFVt4+36H+UHRX9edQdYW4MuwkCiPWtFjaqU67o5kjQiuUAwGb1CQ
         0Phw5YHknvvvfLKg5PPGiCDDPu5/TU0OwYnORMI+i04C/f7dWVKtmsCI5iFuZyuxi3Ye
         Hm//6lA8WVYSVXXKFqe9nPzAJiaYrPUgxAfXs43nDwYCqzdHZtfaItqfvHQZXMf4ayc1
         qP0aMP7rRP4Da6ltjwW+d1DpDXQz5FuotodPjaNLz0HYWTmpo4K8OQpD6rcldjrb5z+R
         1PLPSyDTSlE/FpVUQ5+EzoEp7xaC0r02LHlUxpI29oRqJpHOB1X8q9ZXbVt7zJEoL085
         Ffzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3sioPF0TASdhHt3I8eITXKIlHOh1IUi54sbEgwoECEw=;
        fh=OxHIkQUBh+KCCj1MhIHhA7s/p51MMPk4ic648DaZBMo=;
        b=HwpW1PDXsf+Qj/JK4SsKXONue8sHmSHRNV/230HdflEsyQ7DST93UkkLej/YJRoEmi
         Jm+f9Xm/uX0OEqzWxjMEjc2CpESgmmbbYB57Tz4mVAqhsDDEFmYjaNJ1YfkgPQo4XBfQ
         N14X86VAoHHwFxI0Hz5ss4olnlkgQUqU4cjGb9+ux91BUH8fT3uubQNDL5ZgRuhXsFbZ
         h3cAcVCHb9vcQrkfLdJL1PkFeSZFLVVe+45ZcVRKXHMf2lQfoBN0AnuHDSUs2kradVoI
         kedCRe9TeUhVjHu0A6lq1nlUI8BZOhGwuF/+Ar/ZIJZHgUX5SJ9sx5qom3hZpge2mUIN
         2x4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=4gWnbb0J;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730993261; x=1731598061; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3sioPF0TASdhHt3I8eITXKIlHOh1IUi54sbEgwoECEw=;
        b=nEthvTZIeHNILLS6XltjYYdDauH6+1mmWr+mUA0inxoGNc51Ak78AQFxHpPeXVV/43
         DvgjQyUDzsjHjgfKNgVNuFtXio8Hapq6/W1Y86v2v8h+lLXlZU1hZBy9yKEeMDIHDiqh
         EjzrvnTZSUm6SDsG4JQHEZse5D65cZESLIZ9UGqt4xMZXTp8D4juf0zJvbKBJX63HKm/
         VC0wTWD8LV9+uS1hVWA9RlFQvCMR3zYkMJ5S6t3vBnNQGJlkTZKOZMt0KikxrT2r02T4
         8r9k0FhUEIZPH9UZaG2Q8DoRKfOP8Tb5CVFKBZJOfk4AP1wqFVCKqr1DgxZVGgjAhyNr
         /28w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730993261; x=1731598061;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3sioPF0TASdhHt3I8eITXKIlHOh1IUi54sbEgwoECEw=;
        b=a/uT6rSLRgmF4+rfzX3uzwOc7Ow51cRRIvmx3n+s3r0i2TnrGvbMopvBEkTxnPoWjW
         Q3QF0cuEl8opfSpWLg01t2lkyNZ+vGtvVWdoeOS5sISa/ja1z2oyaK0EvHGw35mGVxEQ
         YHs/tghoLnfD4afcgYrp+QvlRkiRgsPagvI0F6DAjRFXzQx1YB6BjlWw8g1dspFoGxZR
         SBJ3bxXxPDQwymC7vJtKBHPADw1JxIqR38XmonFsxgQOynXQlNP/TUi7w4kmPSE7cOF0
         xRjmIaMTeXineUossOUJ8Dss50Oksxps6FCx7S5EQq8U+e0HU1MXcjW9TGWcZ9LHdGdR
         6kGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUYy9BszsG8cwzXVdKYo/w4qNSZNRu5Tp7vlYfcPMjkbIlF1Vxgh6+DxtejlKkl63gR3ThoeQ==@lfdr.de
X-Gm-Message-State: AOJu0YzvRdwjxKxCHuxQtAVfS5Uh/vp+obRN7KGmM7Cl2Ilf/qi0nTVO
	UF2MSP21kWiqr9TZfNEm2g406pmNtIB+aClILaIIeKJoc41Ns7YJ
X-Google-Smtp-Source: AGHT+IE9BxcPm5dttFsyuQTllv5JE7t5IgHCUS36LJH426CHxr1k0Ln3OV4O2AELk7CaBeymXssZng==
X-Received: by 2002:a05:600c:5118:b0:42c:de2f:da27 with SMTP id 5b1f17b1804b1-4319ac6f848mr409060095e9.2.1730993260489;
        Thu, 07 Nov 2024 07:27:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:525c:0:b0:37d:43e3:53ce with SMTP id ffacd0b85a97d-381ec2ef4e5ls495294f8f.0.-pod-prod-08-eu;
 Thu, 07 Nov 2024 07:27:38 -0800 (PST)
X-Received: by 2002:a5d:4a11:0:b0:374:c92e:f6b1 with SMTP id ffacd0b85a97d-380611585f8mr31806809f8f.23.1730993258154;
        Thu, 07 Nov 2024 07:27:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730993258; cv=none;
        d=google.com; s=arc-20240605;
        b=jSjN2qhom/zV6EP8LGVz5lb/oeSpFWxz6AI9yhSiS6BbpMmq/mAtOIuv0ZV42Y35PT
         9nM5gs9LqtphbBI/xIYoSlfPwJRkridKdBit+GhakF9fRgJThmhf/tjGe7+2RBYcner1
         TO8FS+aUfUYyMGupjWwe10tQwkE2YkH9Mc1UX2cYw8dNQ8vqiY/tMulOIUT1IVka6i4I
         50A04QUkRuQlfgKxrkibwTs3cqbsVB2qz0W1uKbsN/doCtXfxQrnAsLmHMFzmmejEbBx
         ME6McVlAQvRua2S9kkOra4ofjijVow7ylhTiOk8V0UTUsHNFuvqTqo6h8WC5/lIt8wqi
         C8ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=D9GAkp6axrm31ZMYGbMxCuOZ4EkrG3h1hb4DuwNIX7w=;
        fh=MOSuA1H8QGDNXmm4cbnRHrcIY2Uk2qJ1ER8N4n2HqjE=;
        b=OnYvnkkQLVsrGtUjvh7Ipg9ikYZ7m7/3ABN4JOBSTlwi7uykesreH+BSn1I4E7OjS5
         3GFSXjyzJBqYJSRwY3HEmlRuBJla3/OGqKYqdYnGeD1C3Z8YVT6mFKi/MkTG5aosnXZD
         UtqqGFTpmNEVHa3ue78KQ9Xu3AwhDNgNYUqg6tPJMwLWvh1zA4iELrsG/zJ3K5l1laIu
         Vpioj5WyqhAe5cb1u0mmTpSV8gzDGzKCmfPYbNRFRZkhIt0Kg256iBUE53VCqPiMwQFr
         IUWaxSNvrtcM3hAZL4kBk/cEDlkkRkWyw0MqDUZdwHk0NOfgn8bSfcOKnTtxKnN9Kp6J
         lTbw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=4gWnbb0J;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-381eda09913si31665f8f.3.2024.11.07.07.27.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 07:27:38 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Thu, 7 Nov 2024 16:27:36 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: [PATCH v2 4/3] scftorture: Wait until scf_cleanup_handler()
 completes.
Message-ID: <20241107152736.BJPBLXGO@linutronix.de>
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241107111821.3417762-1-bigeasy@linutronix.de>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=4gWnbb0J;       dkim=neutral
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

The smp_call_function() needs to be invoked with the wait flag set to
wait until scf_cleanup_handler() is done. This ensures that all SMP
function calls, that have been queued earlier, complete at this point.

Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/scftorture.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index 1268a91af5d88..ee8831096c091 100644
--- a/kernel/scftorture.c
+++ b/kernel/scftorture.c
@@ -552,7 +552,7 @@ static void scf_torture_cleanup(void)
 			torture_stop_kthread("scftorture_invoker", scf_stats_p[i].task);
 	else
 		goto end;
-	smp_call_function(scf_cleanup_handler, NULL, 0);
+	smp_call_function(scf_cleanup_handler, NULL, 1);
 	torture_stop_kthread(scf_torture_stats, scf_torture_stats_task);
 	scf_torture_stats_print();  // -After- the stats thread is stopped!
 	kfree(scf_stats_p);  // -After- the last stats print has completed!
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107152736.BJPBLXGO%40linutronix.de.
