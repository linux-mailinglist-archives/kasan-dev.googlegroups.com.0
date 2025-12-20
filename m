Return-Path: <kasan-dev+bncBDV2D5O34IDRBAGITDFAMGQEMWNTLMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id E0137CD2726
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Dec 2025 05:20:18 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2a0f47c0e60sf58295635ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 20:20:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766204417; cv=pass;
        d=google.com; s=arc-20240605;
        b=QLnB2w4yjV/qF8sXwH6vW6i9GO0jrThibGvGLu3NHZy3VjY3U3/6+9np60o7BonIQW
         dwRSjrChzLFK+XZJvX1ItX9MFnprFwei1LHRVIf8Ldhoh1N2ufzh8O4QjMWtr9jSjXM+
         y4HjGS32G+E2YGBlQt23sQ59cxxAOzkGzotO4j8p2oXlMOt6J5u4mwf9hO4jlPP6G5hB
         zP2PIItA6Us+ZKOOYMdrkAyBtKzh/7LHNVdmgRekMnAaKtBUppjpGLHcU0uXUPbxkPVS
         BpCPBW4FkmXA9LR+rLQvAWnvs0HNc6o94tGZipHQD1ghPiychjWPOmmH/pne2MLAthMQ
         jrAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:from:to:content-language
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=rLgXNjx6PHPcPRDpk0+iUQSMrB+HBzw/mjFhszrnyFA=;
        fh=oTolelItimMEcAMqbxZPNSVvGhkOuBiwtbgKwPy/9Is=;
        b=dTt5WavjtfjRwBtGhPmwRgF9LEiko1xWfC0KUNbdlSzAZ8uKmfThdfdufC0Lq0grFa
         tELPJq53Mo6aRaHx4V5LQ7LFG/mdld1ns3FXLj3igGXwdmT8UL2uByW7+tOaVoJCUDoe
         +pG8GzC4Sbs79mzQdRDn/paB49esFAaep/uZOu80hjIdsMNJ+ymw2QY+3bspOfFT2MEq
         +afc1G7arNn05HU9TFLkJkCQzdbCsjG7LMEZT835JB1G7s5oiEMfMpI2BLIVfXp5RW/n
         6vpYr7DcCoimyfuRj/w9PYTsU/Vk573dyDpujWQBUmazR2GdbcDJB2zbSmT0bM+R14MA
         BLfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=atoIBtVN;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766204417; x=1766809217; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:from:to:content-language:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rLgXNjx6PHPcPRDpk0+iUQSMrB+HBzw/mjFhszrnyFA=;
        b=UzdCuIdEUvDwOrI3rdTqrdMgjKy/O2gF03yKVzaCFlal3uFF8MGhSLiBPmA9EJsVPp
         Gx/LPt/9JYo3FpB+5imdHDd8NnqreqjZUfyvzORdk1mC7nPzo/Efgn8/uQ6uOfZKp+po
         dAH5DfeI3sB74Oe3fvHC3HHeH4CgSaeeQUR4qZHZQrNXL6dMIX9aC9CzFNrZ7CS/Aehh
         vRYds7Ut9Xipt5QraHEuEw3Qunoq6Bfs6DubxBLHQrLDET4R4OaVCT0uTBceSR3naaPV
         sdZBHbWoiqqd/AUY6hBZ05aCpjCYlkAwIEZpWytIzLNIs1KF/dsDhlD8TzNfVRoCnCDX
         EspA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766204417; x=1766809217;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:from:to
         :content-language:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rLgXNjx6PHPcPRDpk0+iUQSMrB+HBzw/mjFhszrnyFA=;
        b=aHnjJdsrriYHw75eN23PFfD2ma/xtNXSxIzQh46gRB1Y9raWKjPhLUlkFfEeWM4F81
         +YTEXjIP2WJRQUF/nx0ZMXbkJGftlvSRJobTNGG1o6K0sj/XN7QZ/krLwLExH/xLu1Wv
         Jio2ky8TYSB0GRgcgCsz+KV08jiQM7VG3zLeUX1M4laO8BpkUNdANPbZ7942qEuPuTcL
         eiYIP25BrzzteUtEkIgs04qv8+1beJ0vL5DN1HjO9A7M7gT2h5uRuvt3iALFafWy3hWi
         1WoGGe29GiUFKyLwqFHOSacH1prwdXq4DMDRl7jT0GEGE9rRS3QWuDcBSwtBZX2urvK0
         wUqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVYg2VyJThx+wyBIhQSTrsrjoWfItbCMJxl9QGDf3cR9KE7GQtCQ9Qm2Q+Y1UqAcnK9lxIfuQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz1VtHfVfcTiLgkCDT2EMl4oRGar0HdXkrnmI7ls+69iFh/BcfB
	Lh6f682Sb5WWVfyrIhVNtvBvscQMr19wRw/ZRbcODwEwuHa36jVNVD7o
X-Google-Smtp-Source: AGHT+IFdnZNRUnVCdZjllFRlyOsnt6vIGbLcZCzwKx6B0G7WMW8SO1WnIEEw9QvcES+q0yhMfDXPPA==
X-Received: by 2002:a17:902:e550:b0:29f:87f3:9c22 with SMTP id d9443c01a7336-2a2f2c4cc02mr53002375ad.52.1766204416759;
        Fri, 19 Dec 2025 20:20:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWak+AHvo0Ov7kdviNntGDDbU2GOhENsTp9GiSQPzLkEYQ=="
Received: by 2002:a17:903:595:b0:298:e5:d97f with SMTP id d9443c01a7336-29f23579968ls92492205ad.1.-pod-prod-03-us;
 Fri, 19 Dec 2025 20:20:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXNZJt7rpgLo+mM3g7qBPdzF3RdN83GD1Tg7+t0nXOX2+eUR0+v5Vw9eHlYtU88EgO0lobKh1E4LJg=@googlegroups.com
X-Received: by 2002:a17:903:4b28:b0:2a0:b4f6:5595 with SMTP id d9443c01a7336-2a2f2b54b59mr43035835ad.50.1766204415334;
        Fri, 19 Dec 2025 20:20:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766204415; cv=none;
        d=google.com; s=arc-20240605;
        b=TBmAtP3148amXSfcRAaheCL4JC7gL+jZs6D7vtt7CTTkWbe4NZg5fbX2U1S2rK696t
         RmC4fj2GDZ1llTH1T/XAjzuhXkVd9Ykjx0uf63O8KkV2I31QHi6jE8uZj0NoxJ1q0sgh
         MfNdh3ZcKVWtUsKIqrCXBF3WyRZIjzODEEk1SttlQvW6j1AeTA1lWi68vhtlFzZfTtrD
         uXk2kbFnyWS2i6rg9nhWBXI7Tcgm5UfIwaKogMFTtkTS+jOkZreJuj0a7lO19vAh3lYU
         f898UabZF5LMKKTkfS93q4//8JcJtyoa+aa+OgvjgjLkLE0yhOQiZxdDU8TPCvKrBuhM
         4n8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:from:to:content-language
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=fKaEL6Ojgmgiqu/WwkiRMd6jGBm5hHntfnKxlBYkrCU=;
        fh=2Vs2jZg270S9WspRCmwN2ZYL9XyBHPaRFXGnFYgU4xg=;
        b=OTWHGEKD+QpEf60IB7WQtJ3+Ejhhq4Sx3wZCWcApNnKyIquFbx46SRIsjvCC6jxxQi
         alhmvrZ/KPE8rN4Xy6v92ZFa1pEWtXl9Ku8SekiTxSFIt3OIEXI56jJgJjvA+jJ7Sf32
         fdvGJGZd3ap7PYLpcNN7J3E0S7vFA/hC8kx3fJwohr+0ONhaqkSW/nNpD66+uCqDxhv5
         Fal7ZnyH6/L2lwL26YRl2UmiQ7nfCrlZsoL7ondHdSMeSJgFhyZK4syEB0axAjt0MqBJ
         fEVOwNXNtiokZXQZbOgC3GyMIdUWOT8XSXWeHF1hU7YiWaFLDRtiSzc3qdDymNcSeGFP
         WM5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=atoIBtVN;
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a2f3cf69b2si720395ad.3.2025.12.19.20.20.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 20:20:15 -0800 (PST)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.43.113] (helo=[192.168.254.34])
	by bombadil.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vWoRy-0000000BI34-3G7H;
	Sat, 20 Dec 2025 04:20:14 +0000
Message-ID: <90e419ad-4036-4669-a4cc-8ce5d29e464b@infradead.org>
Date: Fri, 19 Dec 2025 20:20:13 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Content-Language: en-US
To: Kees Cook <kees@kernel.org>, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org
From: Randy Dunlap <rdunlap@infradead.org>
Subject: UBSAN: array-index-out-of-bounds
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=atoIBtVN;
       spf=none (google.com: rdunlap@infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=infradead.org
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


from kernel bugzilla:
https://bugzilla.kernel.org/show_bug.cgi?id=220823


Dec 15 22:01:52 orpheus kernel: UBSAN: array-index-out-of-bounds in /var/tmp/portage/sys-kernel/gentoo-kernel-6.18.1/work/linux-6.18/drivers/mtd/devices/mtd_intel_dg.c:750:15


(from drivers/mtd/devices/mtd_intel_dg.c:)

	nvm = kzalloc(struct_size(nvm, regions, nregions), GFP_KERNEL);
...

	for (n = 0, i = 0; i < INTEL_DG_NVM_REGIONS; i++) {
		if (!invm->regions[i].name)
			continue;

		char *name = kasprintf(GFP_KERNEL, "%s.%s",
				       dev_name(&aux_dev->dev), invm->regions[i].name);
		if (!name)
			continue;
750:		nvm->regions[n].name = name;
		nvm->regions[n].id = i;
		n++;
	}
	nvm->nregions = n;


regions is a flexible array in struct intel_dg_nvm *nvm; [see below]
regions is counted_by nvm->nregions.

Question: does UBSAN use the value of the counted_by variable for array bounds
checking?
If so, that means nvm->nregions must be updated before the array entry
is used. Is that correct?

If not, how does UBSAN do array-bounds checking in cases like this?


struct intel_dg_nvm {
	struct kref refcnt;
	struct mtd_info mtd;
	struct mutex lock; /* region access lock */
	void __iomem *base;
	void __iomem *base2;
	bool non_posted_erase;

	size_t size;
	unsigned int nregions;
	struct {
		const char *name;
		u8 id;
		u64 offset;
		u64 size;
		unsigned int is_readable:1;
		unsigned int is_writable:1;
	} regions[] __counted_by(nregions);
};

thanks.
-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/90e419ad-4036-4669-a4cc-8ce5d29e464b%40infradead.org.
