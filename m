Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBPF2WWSQMGQE25Y4BNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 5826A74F09C
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 15:46:38 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-51e3713ce6esf6015150a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jul 2023 06:46:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689083198; cv=pass;
        d=google.com; s=arc-20160816;
        b=UDASMAt4IQmQXqAQXbZGaE0mGNVuR44lj7+p4eCOL/rEzdI4HdNdw7maVmFszqk/Gs
         8rQugG3hvVij0S/GQLxCkvMpDPguJ9N1T/EJLWZuSeWpkp2MjV5METYIAkFMIwxwoj9l
         j+6M2FdXR50oIF8I/hzHYAnpMTMm9bY9ZS+RJwevVViwNrPsCiV5R2P2J2izBSBP6EOg
         g/aRwnGb+SMagpZTz0QW0yJjVD96yKg7Lt3Z6LMxYcBX5J4yTbvY9Ytg8CgoPzCdKmKn
         6cCOp9AcDKpdRI1xT5AU/B5PDOWi8a9SoYMf+vl6lCXK/4geEsazwJoDf+52UKdpD+Pc
         DcKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Opg8Ew/0vKMjl0W4JBPeFTHUwBTiRuUe4ff05xnnApk=;
        fh=5wkMzutboah3mIJLA2vngQ+rKosaYb0XpIOjNELWSA0=;
        b=rtbHrDb3dT8W76b6UgJfc9jlP3vigAPCYAP60G0y6Ki2EWrOo+JJdrh/G/74hdlFA6
         G4tex41cAe/BfzARrr7AuBHrRPzWDo6RrpNIxwS6QIy2mDqRrk1sBFNJeo09KgcSZevc
         YIRCDSdZ5NOrM5m9PdMn2gL81EUQ33y16CtnVcPzwSKA+NyRVGBRY+P/+1k4+1g7etTQ
         oMTNcPSBxdKoEtZJyXZW3Ttu7tm/HCtYPo/QmHdhxvjHCD8p7NFaCSrYNwd9p6mXZdl+
         TUMD+9dsn3mDFRY+4fpYxN6+6e9pZwAy3xvy2iMlLrv5CYNxrRqXuAsd5E1JbcDUvCcQ
         qawA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=acou4bQD;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="Zi00M2H/";
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689083198; x=1691675198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Opg8Ew/0vKMjl0W4JBPeFTHUwBTiRuUe4ff05xnnApk=;
        b=ECK7/uSYqfDj3ztpbeCKW82Cx+0Y98Iu/FXIajCjeIqDNpS1L/NlEdTCx7/kzkh6j6
         tnQK7zfgLmw76WOCeAzmRTz5ZOBM6T65SnCbfYyX2cXILbtPks1q0y6mmOafF/4tyFsA
         qcv08iy/pfMgJOOuT/lne8PFtggRa5cpBefaqrh1r2s69L1pqHSSJebWZAfNzw+TsJBk
         umrYcCg8HxDexuuk/lA6yKVgGgAlN3hWX9BOXYvgDTGE3GM3I961iTTS7OYV5WIMFea2
         dIxA0dnW1CAAGSq92zycNhHPwNGlW2pQNfKfhvv18yyRX5SC8Mhyth9MQUfuXrOqCdoH
         Ktqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689083198; x=1691675198;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Opg8Ew/0vKMjl0W4JBPeFTHUwBTiRuUe4ff05xnnApk=;
        b=B6XmhwmzSSCNKmj6scMS9vqF37SsXi3o69KeAHvSHDOD2OgR0zbjFpxK/c+4mIqCjD
         ZU95VHv2jTScjziJpGMNbaWpBiLUTzMxmuInKmuoPFOhS+DE5CyjU5XSIPJSfq/ANViR
         iVRRUpskWpZKiV0KJwve5/G7lkp+nR2UnQbh03O1fkRZgOi0zW6aKrJM8w+7Jhk1AR0L
         19O7gCZ23xvGpidtQHqw7fRAm7BRLnZrURUrR2Pm0Jiq0HZXtGliz99YdpenGHg/+L3d
         FhkvLc8Ooes346p8tZ+XDNlHAR6fBtqBB+eLjdEttWgIm2r5+zdeQhJxBslbr0xRSZQq
         Jr1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLYXaPD9XYpaIdrpzg3Z6QA2AiVx3OmP45/RU4u9D7Yd7p91+3jP
	/PyqArViD0jxRK/ngcB/Bf0=
X-Google-Smtp-Source: APBJJlEJ9j52d0DySBt6RUjxkxPqB9PbGDdWrQQxHNYQ1qpf7GBiAXAvpPg95gAL6seBMdP5NijDTA==
X-Received: by 2002:a05:6402:26d6:b0:51e:2e6f:70fb with SMTP id x22-20020a05640226d600b0051e2e6f70fbmr21040431edd.6.1689083197266;
        Tue, 11 Jul 2023 06:46:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d3d4:0:b0:516:64b2:cc8a with SMTP id o20-20020aa7d3d4000000b0051664b2cc8als107701edr.0.-pod-prod-00-eu;
 Tue, 11 Jul 2023 06:46:35 -0700 (PDT)
X-Received: by 2002:a05:6402:49:b0:51e:22db:897 with SMTP id f9-20020a056402004900b0051e22db0897mr18290168edu.11.1689083195509;
        Tue, 11 Jul 2023 06:46:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689083195; cv=none;
        d=google.com; s=arc-20160816;
        b=GbPVk607DAAemKuJ3G8uBxZud8LWuQttAArJM0P47MCm04uGHRrXUXOrL2hx4yrfa4
         fYv20YD3IDMFYmUnNwjFP+vxJIsyOSIDS7oXEPL3uTbFgaeXHxsHvcPx8994fOSJWAEt
         AUqYprcvWxuucZEOxCDClsA/mHNgOxprwMuRZ9HnTyOi4eDYw/noMwx2It3+r7vjfda4
         dVB2gTOg1t9FnqldUkMd0Ws1p8r2qTyv3v8UtDiv7F62HHIPIPJQgT6D81+PQLr0KPnD
         oLKXEV/6eqx3YEWAwvyiESPi/GAv2wLQUw0ygWnQrjKeP0ELjYsuUBQeqpJEOO/jH1Vt
         QU3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=tmUBux5e1ki7qsINZJpfH2z48bDyzUotuR1CpySUCaQ=;
        fh=5wkMzutboah3mIJLA2vngQ+rKosaYb0XpIOjNELWSA0=;
        b=04/640+zwvG1xH7E1f8B6KBM1eJ8gCOfHF3sVsiM5uaTdBZAhrOEt92+LsttF9/EGE
         cKhP0AZLM5MwCffKKzo1i7MyE2qQcUfgJsiWKttes2RT3rs0yyNvp+NoO0ISw9d9/FVa
         r2YQhfhyZs0aLlTT30hGYkJBd8tlg9xu9vXRkrRyuvS3W/6digZdNsNiIWI4Lic/FutF
         Ravbcvgn3hOO69lGy8dzDNmWC6Jc+RLFY9XngIdo4242ODEKECa8RBTtNZn1IWy6wcIn
         6zBk5BTnTSy9Jcz1PGnsoHWy0qQ/6rwdiuvi7NombaHXp4az7+sg1dPassuPM8a1vaX4
         R1AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=acou4bQD;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="Zi00M2H/";
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id d19-20020a056402401300b0051e6316130dsi112599eda.5.2023.07.11.06.46.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jul 2023 06:46:35 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4C55622194;
	Tue, 11 Jul 2023 13:46:35 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 10FBB13A63;
	Tue, 11 Jul 2023 13:46:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id iPqDAztdrWTSYwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 11 Jul 2023 13:46:35 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	patches@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	Matteo Rizzo <matteorizzo@google.com>,
	Jann Horn <jannh@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <keescook@chromium.org>,
	linux-hardening@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 2/2] mm/slub: remove freelist_dereference()
Date: Tue, 11 Jul 2023 15:46:25 +0200
Message-ID: <20230711134623.12695-4-vbabka@suse.cz>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20230711134623.12695-3-vbabka@suse.cz>
References: <20230711134623.12695-3-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=acou4bQD;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="Zi00M2H/";
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

freelist_dereference() is a one-liner only used from get_freepointer().
Remove it and make get_freepointer() call freelist_ptr_decode()
directly to make the code easier to follow.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 16 ++++++----------
 1 file changed, 6 insertions(+), 10 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 07edad305512..c4556a5dab4b 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -397,18 +397,14 @@ static inline void *freelist_ptr_decode(const struct kmem_cache *s,
 	return decoded;
 }
 
-/* Returns the freelist pointer recorded at location ptr_addr. */
-static inline void *freelist_dereference(const struct kmem_cache *s,
-					 void *ptr_addr)
-{
-	return freelist_ptr_decode(s, *(freeptr_t *)(ptr_addr),
-			    (unsigned long)ptr_addr);
-}
-
 static inline void *get_freepointer(struct kmem_cache *s, void *object)
 {
-	object = kasan_reset_tag(object);
-	return freelist_dereference(s, (freeptr_t *)(object + s->offset));
+	unsigned long ptr_addr;
+	freeptr_t p;
+
+	ptr_addr = ((unsigned long)kasan_reset_tag(object)) + s->offset;
+	p = *(freeptr_t *)(ptr_addr);
+	return freelist_ptr_decode(s, p, ptr_addr);
 }
 
 #ifndef CONFIG_SLUB_TINY
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230711134623.12695-4-vbabka%40suse.cz.
