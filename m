Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4XAQWGAMGQESIUWNJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F250443453
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Nov 2021 18:08:03 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id d13-20020adf9b8d000000b00160a94c235asf7628983wrc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Nov 2021 10:08:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635872882; cv=pass;
        d=google.com; s=arc-20160816;
        b=sZzs0YbRLeYSjeI5+wOLSceX+t0mm0q61Gllj2vwstGnbcMpwq8tYSxoh8cbME2Eua
         dYvqml5aXFl4HGxKCAFwEMnz+4tw8mxnfiXvAVOXxfcdVGeOHcGwERlbs5NQMDaoIGO+
         gaTM78eFLJRI00eINjPkw3VtHiFV7gV/pSNVPBMlTOtk6220z0ZVvLai0SKBpy4DrYpK
         QGlzjz0e+2spl9glKWWSgNTaPX5QHkBOLwMF6lTcBoRh4jCjQkoPTC1BllI2j4KlBlDR
         9jjNboR1KIgMuttpiX8+zY/IySNVS/lM4nZ4SyvlcBiDn24Vqowb0mcBezmsBMruKWoa
         oSTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=SJ2KxgVB65pk3lxfiw4TPSDhkipbMgYezAJJ2MO9nII=;
        b=ufE/D5dvlfvO92QY4fU3gKOCixqng3PopeY7eYz6P533YeagSjTI3/eh2hZ0zlun/R
         uK2rKizxD20xKJDMeqEhEBOlKSri6JOUe8IRaxiPEyeB0d098PdbM2nl6HGL8KAPy7c7
         +hrOIu3QrmDdS9ONaU3hyTK37wsI3kb/qy1np9PQJveK8KVH0IvZra68nj4lHwjmWMrk
         eBx2eR3tLOvxLWUSYMauwzZeStwXPsLarvUtGMqfJdZC06ug8bvjc51vLQU8/ZeBRWh+
         fjYjyUUI72ynnwIq6shERGuzjFBO7JzBdQJmXT+bVdS1neq60X54YRLuQdjGy7rLXH59
         7orw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=h5ZsJTLf;
       spf=pass (google.com: domain of 3cxcbyqukcwomtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cXCBYQUKCWoMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=SJ2KxgVB65pk3lxfiw4TPSDhkipbMgYezAJJ2MO9nII=;
        b=clzlivR+j2U5BgkzOrhB4QfJBIeolD0tcTIHMZOYJXGgZFjokEDKFfS/qVrctt7AXe
         Ry2qCnUPmEwX9td330oaZklPmfUDc6MDLAyGGsKqT0nI1vdyCRvvA2FaXaMypb5s+ccl
         NJM6JyDTSUST2RNWPVwOzOLZnF96vSk8JHsn+XD3q9mjhAuQYLQFcWZbeoNR6cOhFe9l
         8qHRkajgWx2dgG6SyJVNK1AvZruzUiAnjkzk89eU/CSh8LvM0Acbg6qt03gaZeBBc0MN
         9PuzSyxrkyMGYKjhMVenhstUWfJcKtAqlrb+TPRC0zH++D58Vyhdw0ap1oRGYe00AY2C
         n2tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SJ2KxgVB65pk3lxfiw4TPSDhkipbMgYezAJJ2MO9nII=;
        b=dCeewGKBzN1K1+7vwRTy+nQ39i9yNOat50ukZ+abHPyZd1NbCbcZPcWQXx/eYwsS85
         H6BsqFtxCXAKLKVCLEgc3GO//Pv+Cgzvfv75dHm3X/auPTlFIIoV16rGY/n172Ekffmn
         WGXZEDGCf02PQ/lGPjQ0ubxmtMe6omeX9UpcRg6a9HRXrFVT9PPZa6St1nK1B9QKMnx+
         HcvCwrviwFpbX4H8CONqQ+vVRE6OWaqvuOBEdKMvMmYcpLweWwRnWQuyMk/flmejLwej
         3DN6c2EJnlOu07krKson0B1/mK6gRAjYlmwd6lqq9icx2hJZ1epbaUcdP2bQUwIjixEL
         qtFA==
X-Gm-Message-State: AOAM530Di4IREO+HhN1vTCTKEZTFRRD2Nxj84wnM0HJhrPLhDcm39rmI
	M5uKogK2os7Gxc6siERrH1k=
X-Google-Smtp-Source: ABdhPJzrOQT7sSVU/FIr80iMlA0KAKfP3urvnzlrID8HjdWpB1oecPmjzYAQFhEeRIuYQAwPROjhSA==
X-Received: by 2002:adf:9c02:: with SMTP id f2mr49426637wrc.201.1635872882862;
        Tue, 02 Nov 2021 10:08:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1986:: with SMTP id t6ls1594577wmq.2.gmail; Tue, 02
 Nov 2021 10:08:01 -0700 (PDT)
X-Received: by 2002:a1c:f405:: with SMTP id z5mr8597841wma.72.1635872881894;
        Tue, 02 Nov 2021 10:08:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635872881; cv=none;
        d=google.com; s=arc-20160816;
        b=lPVdGfoz1XBwc30dFeSAWCtNpnbAqKzyeAwDGpxCLLzwdbL0yvXBzIowvBDxWt1zyB
         Vf+p4Xpikg2uzm/bhkgL0V/FdFOrxiCw5XCyKX3AwhJeDrVZC8HOrxo3O42Zj7y1PDTM
         fAYMWpiQGTFc8pKW9AC+vzQFKvKi2szLHQ/NyJWXQ2tbHS4TFGzis0fUacA7MGJUGXwv
         oZmHS4fkISMLqP2RO6LY4OK6wm6IFTzo2ooOKZExyOP6R2sVqH+Spb7Qj2Q/Ylzna2Ho
         11qzZuA/YT8CrjeiA76LuYyPmOT64/AnFRcGmQ0kb2ISRIUVsHbbRDtkKXi/gieFDnew
         6IOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=VZR4veHDB/Hv5J8c9l5kvLwMvvSzVFvPkC6CzrVLaSc=;
        b=anujqEGmkkMrPnsC9byPyYAKUzaKeNa63m4UU0TnUrYw+KcAoQ1yjnSFS6myO+6nXH
         q/dMRmQoB4mqIsPotpw5y6lEfzS5exzwHsVUWlQ9Fyi1U/S19dB8GwKcsSCgUmuhf13s
         LTvTWBnd0MMsMOZwDuN9lMY1xXpG5X0XHmOrW7PYqtaXL2hHRwGLId3/U2QTUxldJc6D
         2bu76vi7lW0lp1FFIOnn1U7b3H7Msnbfy1eeY31E8Zyc/Qt6aypddNx7d3qGpHuP3iEU
         oiXemUf9LMN56WHyXsM2cHDPSfzSHTMvTKc34r3Rms8xizUFeNwjNGICNKimLoC8e0hm
         8EVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=h5ZsJTLf;
       spf=pass (google.com: domain of 3cxcbyqukcwomtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cXCBYQUKCWoMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id j23si449662wms.0.2021.11.02.10.08.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Nov 2021 10:08:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3cxcbyqukcwomtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m1-20020a1ca301000000b003231d5b3c4cso1445918wme.5
        for <kasan-dev@googlegroups.com>; Tue, 02 Nov 2021 10:08:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:c225:73fc:3369:a4ae])
 (user=elver job=sendgmr) by 2002:a5d:51cf:: with SMTP id n15mr38162615wrv.106.1635872881388;
 Tue, 02 Nov 2021 10:08:01 -0700 (PDT)
Date: Tue,  2 Nov 2021 18:07:33 +0100
Message-Id: <20211102170733.648216-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.1.1089.g2158813163f-goog
Subject: [PATCH] mm/slab_common: use WARN() if cache still has objects on destroy
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Vlastimil Babka <vbabka@suse.cz>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Ingo Molnar <mingo@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=h5ZsJTLf;       spf=pass
 (google.com: domain of 3cxcbyqukcwomtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3cXCBYQUKCWoMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Calling kmem_cache_destroy() while the cache still has objects allocated
is a kernel bug, and will usually result in the entire cache being
leaked. While the message in kmem_cache_destroy() resembles a warning,
it is currently not implemented using a real WARN().

This is problematic for infrastructure testing the kernel, all of which
rely on the specific format of WARN()s to pick up on bugs.

Some 13 years ago this used to be a simple WARN_ON() in slub, but
d629d8195793 ("slub: improve kmem_cache_destroy() error message")
changed it into an open-coded warning to avoid confusion with a bug in
slub itself.

Instead, turn the open-coded warning into a real WARN() with the message
preserved, so that test systems can actually identify these issues, and
we get all the other benefits of using a normal WARN(). The warning
message is extended with "when called from <caller-ip>" to make it even
clearer where the fault lies.

For most configurations this is only a cosmetic change, however, note
that WARN() here will now also respect panic_on_warn.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/slab_common.c | 11 +++--------
 1 file changed, 3 insertions(+), 8 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index ec2bb0beed75..0155a3042203 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -497,8 +497,6 @@ void slab_kmem_cache_release(struct kmem_cache *s)
 
 void kmem_cache_destroy(struct kmem_cache *s)
 {
-	int err;
-
 	if (unlikely(!s))
 		return;
 
@@ -509,12 +507,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
 	if (s->refcount)
 		goto out_unlock;
 
-	err = shutdown_cache(s);
-	if (err) {
-		pr_err("%s %s: Slab cache still has objects\n",
-		       __func__, s->name);
-		dump_stack();
-	}
+	WARN(shutdown_cache(s),
+	     "%s %s: Slab cache still has objects when called from %pS",
+	     __func__, s->name, (void *)_RET_IP_);
 out_unlock:
 	mutex_unlock(&slab_mutex);
 	cpus_read_unlock();
-- 
2.33.1.1089.g2158813163f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211102170733.648216-1-elver%40google.com.
