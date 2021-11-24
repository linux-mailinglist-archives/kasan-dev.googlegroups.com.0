Return-Path: <kasan-dev+bncBAABBYXS7GGAMGQEVH4NCLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id D0A8D45CB4E
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 18:42:00 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id e4-20020a170902b78400b00143c2e300ddsf978015pls.17
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 09:42:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637775717; cv=pass;
        d=google.com; s=arc-20160816;
        b=hv7qeDNH97XZ1zv8+GEsMP/+B3s8ySswSBao6nx3NY/iuCRmE3BSj2Vs+iqoW1FaHG
         WE+EiZ37jQb4nIh+sJYfbpkWaaLKQ69IbrjmxchdwQYG43lH//9+NF9PDSpUygelm/73
         3vXOu7XP0nyGvai4m+WpkfPzTirZQGB1ge0ZpNp9WvT0oy8TR5Lfoujw/L5wVuWQlNo0
         dmFXxKsAccLb73V174DFaL1CGTlVaZGAekPxLAFwIqpA28R0jEz3lLWMrNRC7Ls8VmpE
         P6RF5fASxT683wN3xquZZmHRrKjKbmJjsIY4cns69o30dW/PhXFYXfyBvYS3TS1AmptM
         oSNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=5gVOlgdpnHY/0n/Fmk7BHoJq06O28rqxoCXNFHBALDg=;
        b=ha3nza67qAZR4ql24aeYObCxLkTXMesWtxWFRJ4muY3egzFFSKSxw+n1kpAv3MtnW9
         OiHSc7WdJM4eGrsHU/WZ3+GIyjWDqrnASG4d3H2CNtSXjIorfunbhND4Faim5SMdooq3
         uM2DWr0qgwdvqJh5Gh5e3rNzHoDWnOetgBlhTaiWHkIALgQJynt2jedOjMoSbklPr2YH
         f/wDMdX2XGpgS2wf3ih82H1ryxhCrQwLJY0Lr5l5a8rbWnMLtwzxAWTWOBkJP5MrArSY
         bujMX6WkoLXkFoZtuTr3KU33Bc1bgz0u1+A4ET5aT5PBR/AotrSApKQ6nLYNhYqrUQwG
         6JHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GM1pbrcl;
       spf=pass (google.com: domain of jikos@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=jikos@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:user-agent:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5gVOlgdpnHY/0n/Fmk7BHoJq06O28rqxoCXNFHBALDg=;
        b=WKXTSkvjvvQAKFVMv7Re8ZCVDi1fWdKYhSQw9B+hNwlpZCQ3icHb6XXfrP/e+g+7Dz
         OoFplYIVQAcpSSTyZqmXEvV1Pj3inWiZFruivzJyuwz/7jJ+dGdESJgJPl9q4ESEzmRB
         gygfkjQLWKEvZR52aIkFrr4JWmJM1QurrYvdBI0l7oCePj+QX/YyttwcrmGAf3++Rt1E
         JaYuv1zr9Ug4okDRkyyT6zHeU1f5c4i684ufpj2GyOqDWryt297YrYrYuzWRKFOkvZcn
         4PqEz2jBFjMHWYRonyy+nV7/5UUZ1sldAjXE6SWOBaWIlIWMbTHNCDJa8oWahVBVmGCG
         BODg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5gVOlgdpnHY/0n/Fmk7BHoJq06O28rqxoCXNFHBALDg=;
        b=SRA4FwYorwrb2eahCCDM7Eos//gSrs4V9OnocUcW6uIbhFPMyEvVV/o0S/KmTroNCe
         kpZFbFPkw8kQJzHksUR0jFN8awASvVOxwVE3Ts+0DauzGikdgkW/pqReBj+mGRWtqBOl
         ahtE3WqtqAKSxrpRfIWr1F6/9sb7DXP0PimcCVH1w8vdb2qZFO/RXkfcDeSa9JESldxx
         H/XV2EdhyKsPyWxBm5DMT9JEaT/uzyVEYmYmBQaGMy62wrYifiYB/7ekejtRlHeAdM1j
         1ok5wY76vSSU8Q9dR8jYJH3/T3wOuZzBpkaKkZOQMq6q/IQi/UtPHhGkYip/1bzwn10h
         SgPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324SGBJYhyznq02pKNMuQp3EZmX1kD3CfHZVtNn6WRlOwIxvJ4h
	GXeOVtsTuhD4EM0eBHfK3Ak=
X-Google-Smtp-Source: ABdhPJzko5jhAqOunDEt6BA6LA/7lSQE5qt0/1mPkprijtrhShjapPf2t4VRy1XDwywLRoI34rAO1A==
X-Received: by 2002:a17:90a:7ac8:: with SMTP id b8mr17675201pjl.206.1637775715065;
        Wed, 24 Nov 2021 09:41:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d50e:: with SMTP id b14ls284434plg.7.gmail; Wed, 24
 Nov 2021 09:41:54 -0800 (PST)
X-Received: by 2002:a17:902:c702:b0:144:ce0e:d47 with SMTP id p2-20020a170902c70200b00144ce0e0d47mr20437113plp.69.1637775714636;
        Wed, 24 Nov 2021 09:41:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637775714; cv=none;
        d=google.com; s=arc-20160816;
        b=c9IyE9XlikJ+Wj40McYxRQaplijqJDYMNr7U0PSQ1uSDecteAEybDVxIBRERV8hD8G
         fSpH7gUqQI4JRS3QhWwzl7UbmM8RtM78E7vT0byfIj/5qBeqKcAx7lNnxkz5rEa7qzUf
         jfVaf0PiGCmfjpl+tE9S/TWvL9+hXdid4nSHZ3RMlQ9YBd4cQ3baLbzfFrHoZC0OlXzv
         YJFYR9Xzf4WzvmYhJg6uE/nWUMHA0S0SRjT6MoE8U+xCpcT6FZexPeosAU+Joo2gt/P2
         3DkFTOT5uX5oWfC8E+nbMLmjrDXMX8k8owqR2skU6pv7EWAOKwg8sXUjYNo/RKsvJirw
         E5lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=KGSGa3GG/g1GACPRAS71XDv9dtTswIiFUMgnNOFEIQs=;
        b=ZjaHAZsZqagZPT/KaPI+xgbqlYRq5H/R20yRG3OCO4DYurhucuIWFsdHBeNFfi09ZH
         vTKfeOFchj1UQELY97W//Oqewa8fDoIP6+j0/KKekhPDS8Sd9/AOEplTb4c8JJPsG3Vm
         j/5TLmhusaRJ23QhsaRFdm5s98tYj1rjbDv6mQziv2O3XRGapGtbYYjV2FSEcW3tytzT
         YkX3RlLeRcsbgArCvox6NoCYPE4oVwp6UNR11HtACSC9rQ4SSIS3IXP+UkDhQ3I5nT8i
         u4m6dNWldG2FhfqpPRyxCFsYVLiKIvAHgbUd+F0uvBqg+ZOsSJaADdm/eGkNuU2K53Rz
         OAUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GM1pbrcl;
       spf=pass (google.com: domain of jikos@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=jikos@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c3si30915pgv.1.2021.11.24.09.41.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Nov 2021 09:41:54 -0800 (PST)
Received-SPF: pass (google.com: domain of jikos@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8B38C60FBF;
	Wed, 24 Nov 2021 17:41:52 +0000 (UTC)
Date: Wed, 24 Nov 2021 18:41:49 +0100 (CET)
From: Jiri Kosina <jikos@kernel.org>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Andrew Morton <akpm@linux-foundation.org>
cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, 
    linux-kernel@vger.kernel.org, jslaby@suse.cz
Subject: [PATCH] kasan: distinguish kasan report from generic BUG()
Message-ID: <nycvar.YFH.7.76.2111241839590.16505@cbobk.fhfr.pm>
User-Agent: Alpine 2.21 (LSU 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jikos@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GM1pbrcl;       spf=pass
 (google.com: domain of jikos@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=jikos@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Jiri Kosina <jkosina@suse.cz>

The typical KASAN report always begins with

	BUG: KASAN: ....

in kernel log. That 'BUG:' prefix creates a false impression that it's an 
actual BUG() codepath being executed, and as such things like 
'panic_on_oops' etc. would work on it as expected; but that's obviously 
not the case.

Switch the order of prefixes to make this distinction clear and avoid 
confusion.

Signed-off-by: Jiri Kosina <jkosina@suse.cz>
---
 mm/kasan/report.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 0bc10f452f7e..ead714c844e9 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -86,7 +86,7 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
 
 static void print_error_description(struct kasan_access_info *info)
 {
-	pr_err("BUG: KASAN: %s in %pS\n",
+	pr_err("KASAN: BUG: %s in %pS\n",
 		kasan_get_bug_type(info), (void *)info->ip);
 	if (info->access_size)
 		pr_err("%s of size %zu at addr %px by task %s/%d\n",
@@ -366,7 +366,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
 
 	start_report(&flags);
-	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
+	pr_err("KASAN: BUG: double-free or invalid-free in %pS\n", (void *)ip);
 	kasan_print_tags(tag, object);
 	pr_err("\n");
 	print_address_description(object, tag);
@@ -386,7 +386,7 @@ void kasan_report_async(void)
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
 
 	start_report(&flags);
-	pr_err("BUG: KASAN: invalid-access\n");
+	pr_err("KASAN: BUG: invalid-access\n");
 	pr_err("Asynchronous mode enabled: no access details available\n");
 	pr_err("\n");
 	dump_stack_lvl(KERN_ERR);


-- 
Jiri Kosina
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/nycvar.YFH.7.76.2111241839590.16505%40cbobk.fhfr.pm.
